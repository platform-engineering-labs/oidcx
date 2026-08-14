package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/platform-engineering-labs/oox/provx"
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

func (role) Exists(ctx context.Context, awsProv *AWS) (bool, error) {
	return true, nil
}

func (role) Create(ctx context.Context, awsProv *AWS) error {
	trustPolicy := TrustPolicy{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Principal: FederatedPrincipal{
					Federated: ConnectProvider.Arn(awsProv.accountId),
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: map[string]interface{}{
					"StringEquals": map[string]string{
						fmt.Sprintf("%s:aud", provx.Endpoint): "sts.amazonaws.com",
						fmt.Sprintf("%s:sub", provx.Endpoint): provx.Subject(awsProv.accountId, awsProv.tenantId),
					},
				},
			},
		},
	}

	policyBytes, err := json.MarshalIndent(trustPolicy, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal trust policy: %v", err)
	}

	_, err = awsProv.client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(provx.Subject(awsProv.accountId, awsProv.tenantId)),
		AssumeRolePolicyDocument: aws.String(string(policyBytes)),
		Description:              aws.String("formae.ai oidc connection"),
	})
	if err != nil {
		return fmt.Errorf("failed to create IAM role: %v", err)
	}

	return nil
}
