package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type TrustPolicy struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

type PolicyStatement struct {
	Effect    string                 `json:"Effect"`
	Principal FederatedPrincipal     `json:"Principal"`
	Action    string                 `json:"Action"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

type FederatedPrincipal struct {
	Federated string `json:"Federated"`
}

var Role = role{}

type role struct{}

func (role) Create(ctx context.Context, awsProv *AWS) error {
	trustPolicy := TrustPolicy{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Principal: FederatedPrincipal{
					Federated: awsProv.providerArn(),
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: map[string]interface{}{
					"StringEquals": map[string]string{
						fmt.Sprintf("%s:aud", awsProv.issuer.Host()): "sts.amazonaws.com",
						fmt.Sprintf("%s:sub", awsProv.issuer.Host()): awsProv.subject,
					},
				},
			},
		},
	}

	policyBytes, err := json.MarshalIndent(trustPolicy, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal trust policy: %v", err)
	}

	_, err = awsProv.iam.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(awsProv.roleName),
		AssumeRolePolicyDocument: aws.String(string(policyBytes)),
		Description:              aws.String("formae.ai oidc connection"),
	})
	if err != nil {
		var alreadyExistsErr *types.EntityAlreadyExistsException
		if errors.As(err, &alreadyExistsErr) {
			awsProv.logger.Info("exists: connector role")
			return nil
		}

		return fmt.Errorf("failed to create IAM role: %v", err)
	}

	awsProv.logger.Info("created: connector role")

	return nil
}

func (role) Delete(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.iam.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(awsProv.roleName),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			awsProv.logger.Info("already deleted: connector role")
			return nil
		} else {
			return err
		}
	}

	awsProv.logger.Info("deleted: connector role")

	return nil
}
