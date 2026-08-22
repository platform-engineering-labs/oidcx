package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// RoleOutcome reports what ensureRole did.
type RoleOutcome string

const (
	RoleCreated   RoleOutcome = "created"
	RoleConverged RoleOutcome = "converged"
)

// Ownership tags: a role is only ours to converge when it carries the
// provx owner tag and the exact subject it was provisioned for. The
// tags are written once at create and never rewritten.
const (
	tagOwner      = "formae-ai:owner"
	tagOwnerValue = "provx"
	tagSubject    = "formae-ai:subject"
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

func (a *AWS) trustPolicyJSON() (string, error) {
	trustPolicy := TrustPolicy{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Effect: "Allow",
				Principal: FederatedPrincipal{
					Federated: a.providerArn(),
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: map[string]interface{}{
					"StringEquals": map[string]string{
						a.issuer.Host() + ":aud": stsAudience,
						a.issuer.Host() + ":sub": a.subject,
					},
				},
			},
		},
	}

	policyBytes, err := json.Marshal(trustPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal trust policy: %w", err)
	}
	return string(policyBytes), nil
}

// ensureRole creates the connector role, or converges an existing one
// when the ownership tags prove it is ours for this exact subject:
// the whole trust-policy document is rewritten. Description and
// MaxSessionDuration are set at create only and deliberately not
// converged (cosmetic). The returned ARN comes from CreateRole or
// GetRole output, never assembled by hand.
func (a *AWS) ensureRole(ctx context.Context) (string, RoleOutcome, error) {
	doc, err := a.trustPolicyJSON()
	if err != nil {
		return "", "", err
	}

	created, err := a.iam.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(a.roleName),
		AssumeRolePolicyDocument: aws.String(doc),
		Description:              aws.String("formae.ai oidc connection"),
		MaxSessionDuration:       aws.Int32(3600),
		Tags: []types.Tag{
			{Key: aws.String(tagOwner), Value: aws.String(tagOwnerValue)},
			{Key: aws.String(tagSubject), Value: aws.String(a.subject)},
		},
	})
	if err == nil {
		a.logger.Info("created: connector role")
		return aws.ToString(created.Role.Arn), RoleCreated, nil
	}

	var alreadyExistsErr *types.EntityAlreadyExistsException
	if !errors.As(err, &alreadyExistsErr) {
		return "", "", fmt.Errorf("failed to create IAM role: %w", err)
	}

	tags := map[string]string{}
	var marker *string
	for {
		page, err := a.iam.ListRoleTags(ctx, &iam.ListRoleTagsInput{
			RoleName: aws.String(a.roleName),
			Marker:   marker,
		})
		if err != nil {
			return "", "", fmt.Errorf("failed to read role tags: %w", err)
		}
		for _, tg := range page.Tags {
			tags[aws.ToString(tg.Key)] = aws.ToString(tg.Value)
		}
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}

	owner := tags[tagOwner]
	subject := tags[tagSubject]
	switch {
	case owner == "":
		return "", "", &RoleCollisionError{RoleName: a.roleName}
	case owner != tagOwnerValue:
		return "", "", &RoleCollisionError{RoleName: a.roleName, Owner: owner}
	case subject != a.subject:
		return "", "", &RoleCollisionError{RoleName: a.roleName, Owner: owner, SubjectWanted: a.subject, SubjectFound: subject}
	}

	_, err = a.iam.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String(a.roleName),
		PolicyDocument: aws.String(doc),
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to update the role trust policy: %w", err)
	}

	got, err := a.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(a.roleName)})
	if err != nil {
		return "", "", fmt.Errorf("failed to read the converged role: %w", err)
	}

	a.logger.Info("converged: connector role")
	return aws.ToString(got.Role.Arn), RoleConverged, nil
}

func (a *AWS) deleteRole(ctx context.Context) error {
	_, err := a.iam.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(a.roleName),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			a.logger.Info("already deleted: connector role")
			return nil
		}
		return err
	}

	a.logger.Info("deleted: connector role")

	return nil
}
