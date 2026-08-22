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

	if err := a.assertRoleOwnership(ctx); err != nil {
		return "", "", err
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

// assertRoleOwnership reads the role's tags (paginated) and returns nil
// only when they prove the role is ours for this exact subject; any
// other tag state is a *RoleCollisionError. A failed read, including
// NoSuchEntity when the role does not exist, comes back wrapped for the
// caller to interpret.
func (a *AWS) assertRoleOwnership(ctx context.Context) error {
	tags := map[string]string{}
	var marker *string
	for {
		page, err := a.iam.ListRoleTags(ctx, &iam.ListRoleTagsInput{
			RoleName: aws.String(a.roleName),
			Marker:   marker,
		})
		if err != nil {
			return fmt.Errorf("failed to read role tags: %w", err)
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
		return &RoleCollisionError{RoleName: a.roleName}
	case owner != tagOwnerValue:
		return &RoleCollisionError{RoleName: a.roleName, Owner: owner}
	case subject != a.subject:
		return &RoleCollisionError{RoleName: a.roleName, Owner: owner, SubjectWanted: a.subject, SubjectFound: subject}
	}
	return nil
}

// deleteRole removes the connector role behind the same ownership gate
// ensureRole enforces: nothing is touched unless the tags prove the
// role is ours for this exact subject, and a role that is already gone
// is success. Before DeleteRole every attached managed policy is
// detached and every inline policy deleted, whatever their names: IAM
// refuses to delete a role with attachments, and roles provisioned by
// earlier posture versions carry policies the current posture does not.
func (a *AWS) deleteRole(ctx context.Context) error {
	var noSuchEntityErr *types.NoSuchEntityException

	if err := a.assertRoleOwnership(ctx); err != nil {
		if errors.As(err, &noSuchEntityErr) {
			a.logger.Info("already deleted: connector role")
			return nil
		}
		return err
	}

	attachedArns, err := a.listAttachedPolicyArns(ctx)
	if err != nil {
		return err
	}
	for _, arn := range attachedArns {
		_, err := a.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  aws.String(a.roleName),
			PolicyArn: aws.String(arn),
		})
		if err != nil && !errors.As(err, &noSuchEntityErr) {
			return fmt.Errorf("failed to detach an attached policy: %w", err)
		}
	}

	inlineNames, err := a.listInlinePolicyNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range inlineNames {
		_, err := a.iam.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(a.roleName),
			PolicyName: aws.String(name),
		})
		if err != nil && !errors.As(err, &noSuchEntityErr) {
			return fmt.Errorf("failed to delete an inline policy: %w", err)
		}
	}

	_, err = a.iam.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(a.roleName),
	})
	if err != nil {
		if errors.As(err, &noSuchEntityErr) {
			a.logger.Info("already deleted: connector role")
			return nil
		}
		return err
	}

	a.logger.Info("deleted: connector role")

	return nil
}
