package aws

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/platform-engineering-labs/oox/provx"
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
func New(logger *slog.Logger, credProvider aws.CredentialsProvider, region, tenantId, installationId string) (*AWS, error) {
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

	return &AWS{logger, iam.NewFromConfig(cfg), *result.Account, tenantId, installationId}, nil
}

func (a *AWS) Create(ctx context.Context) error {
	// Check if OIDC connect provider exists
	connectorExists, err := ConnectProvider.Exists(ctx, a)
	if err != nil {
		return err
	}

	if !connectorExists {
		// Create connect provider
		err := ConnectProvider.Create(ctx, a)
		if err != nil {
			return err
		}

		log.Println("created connector")
	}

	// Check trust role is exists
	roleExists, err := Role.Exists(ctx, a)
	if err != nil {
		return err
	}

	if !roleExists {
		// Create the trust role
		err := Role.Create(ctx, a)
		if err != nil {
			return err
		}

		log.Println("created connector role")
	}

	// Idempotently attach the administrator policy to the role
	_, err = a.client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(provx.SubjectIdentifier(a.tenantId, a.installationId)),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		var alreadyAttachedErr *types.EntityAlreadyExistsException
		if !errors.As(err, &alreadyAttachedErr) {
			return err
		}
	}

	log.Println("attached connector policy")

	return nil
}

// Delete idempotent, resources have known names delete and log, but not return errors
func (a *AWS) Delete(ctx context.Context) error {
	Role.Delete(ctx, a)

	ConnectProvider.Delete(ctx, a)

	return nil
}
