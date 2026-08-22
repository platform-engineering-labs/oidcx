package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWS struct {
	*slog.Logger

	client         *iam.Client
	accountId      string
	tenantId       string
	installationId string
}

// New create a new AWS provisioner
//
// create a credential provider like:
// static: provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
func New(logger *slog.Logger, credProvider aws.CredentialsProvider, region, accountId, tenantId, installationId string) (*AWS, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credProvider),
	)
	if err != nil {
		return nil, err
	}

	// Fetch authenticated account id
	stsClient := sts.NewFromConfig(cfg)

	result, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get account id: %v", err)
	}

	if *result.Account != accountId {
		return nil, fmt.Errorf("account id does not match the account authenticated to with the provided credentials, expected %s, got %s", accountId, *result.Account)
	}

	return &AWS{logger, iam.NewFromConfig(cfg), *result.Account, tenantId, installationId}, nil
}

func (a *AWS) Create(ctx context.Context) error {
	// Create connect provider
	err := ConnectProvider.Create(ctx, a)
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

	err = ConnectProvider.Delete(ctx, a)
	if err != nil {
		return err
	}

	return nil
}
