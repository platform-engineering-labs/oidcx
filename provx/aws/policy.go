package aws

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/platform-engineering-labs/oox/provx"
)

var Policy = policy{}

type policy struct{}

func (policy) Create(ctx context.Context, awsProv *AWS) error {
	// Idempotently attach the administrator policy to the role
	_, err := awsProv.client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(provx.SubjectIdentifier(awsProv.tenantId, awsProv.installationId)),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		return err
	}

	awsProv.Info("created: connector policy")

	return nil
}

func (policy) Delete(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String(provx.SubjectIdentifier(awsProv.tenantId, awsProv.installationId)),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			awsProv.Info("already deleted: connector policy")
			return nil
		} else {
			return err
		}
	}
	awsProv.Info("deleted: connector policy")

	return nil
}
