package aws

import (
	"context"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/platform-engineering-labs/oox/provx"
)

type AWS struct {
	logger *slog.Logger

	iam       iamAPI
	accountID string
	subject   string
	roleName  string
	issuer    provx.Issuer
}

// New creates a new AWS provisioner from server-produced identity
// inputs: the exact subject and role name plus the raw issuer string,
// which is parsed and validated internally.
//
// Create a credential provider like:
// static: provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
func New(ctx context.Context, creds awssdk.CredentialsProvider, region, accountID, subject, roleName, issuer string) (*AWS, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(creds),
	)
	if err != nil {
		return nil, err
	}

	return newWithClients(ctx, sts.NewFromConfig(cfg), iam.NewFromConfig(cfg), accountID, subject, roleName, issuer)
}

func newWithClients(ctx context.Context, stsc stsAPI, iamc iamAPI, accountID, subject, roleName, issuer string) (*AWS, error) {
	iss, err := provx.ParseIssuer(issuer)
	if err != nil {
		return nil, err
	}

	out, err := stsc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to verify caller identity: %w", err)
	}

	if actual := awssdk.ToString(out.Account); actual != accountID {
		return nil, &AccountMismatchError{Expected: accountID, Actual: actual}
	}

	callerArn, err := arn.Parse(awssdk.ToString(out.Arn))
	if err != nil {
		return nil, fmt.Errorf("refusing to proceed: caller ARN is malformed: %w", err)
	}
	if callerArn.Partition != "aws" {
		return nil, fmt.Errorf("refusing to proceed: caller is in partition %q, only the commercial aws partition is supported", callerArn.Partition)
	}

	return &AWS{
		logger:    slog.Default(),
		iam:       iamc,
		accountID: accountID,
		subject:   subject,
		roleName:  roleName,
		issuer:    iss,
	}, nil
}

func (a *AWS) Create(ctx context.Context) error {
	// Create or validate the connect provider
	_, err := a.ensureProvider(ctx)
	if err != nil {
		return err
	}

	// Create the trust role
	err = Role.Create(ctx, a)
	if err != nil {
		return err
	}

	err = Policy.Create(ctx, a)
	if err != nil {
		return err
	}

	return nil
}

// Delete idempotent, resources have known names delete and log, but not return errors
func (a *AWS) Delete(ctx context.Context) error {
	err := Policy.Delete(ctx, a)
	if err != nil {
		return err
	}

	err = Role.Delete(ctx, a)
	if err != nil {
		return err
	}

	err = a.deleteProvider(ctx)
	if err != nil {
		return err
	}

	return nil
}
