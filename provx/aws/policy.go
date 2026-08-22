package aws

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

var Policy = policy{}

type policy struct{}

func (policy) Create(ctx context.Context, awsProv *AWS) error {
	// Idempotently attach the administrator policy to the role
	_, err := awsProv.iam.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(awsProv.roleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		return err
	}

	awsProv.logger.Info("created: connector policy")

	return nil
}

func (policy) Delete(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String(awsProv.roleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			awsProv.logger.Info("already deleted: connector policy")
			return nil
		} else {
			return err
		}
	}
	awsProv.logger.Info("deleted: connector policy")

	return nil
}
