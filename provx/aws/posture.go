package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The connector role's fixed permission posture: the PowerUserAccess
// managed policy plus the formae-iam inline policy. It mirrors the
// formae-bootstrap task role. PowerUserAccess excludes IAM, and missing
// IAM reads make discovery 403-spam, so the inline policy grants the
// IAM writes the agent provisions with plus blanket iam:Get*/iam:List*.
// The bootstrap ssmmessages policy is ECS-exec-specific and excluded.
const (
	ManagedPolicyArn = "arn:aws:iam::aws:policy/PowerUserAccess"
	InlinePolicyName = "formae-iam"
)

const inlinePolicyJSON = `{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["iam:CreateRole","iam:DeleteRole","iam:GetRole","iam:ListRoles","iam:UpdateRole","iam:UpdateAssumeRolePolicy","iam:TagRole","iam:UntagRole","iam:PutRolePolicy","iam:DeleteRolePolicy","iam:GetRolePolicy","iam:ListRolePolicies","iam:AttachRolePolicy","iam:DetachRolePolicy","iam:ListAttachedRolePolicies","iam:CreatePolicy","iam:DeletePolicy","iam:GetPolicy","iam:ListPolicies","iam:CreatePolicyVersion","iam:DeletePolicyVersion","iam:GetPolicyVersion","iam:ListPolicyVersions","iam:SetDefaultPolicyVersion","iam:CreateInstanceProfile","iam:DeleteInstanceProfile","iam:GetInstanceProfile","iam:AddRoleToInstanceProfile","iam:RemoveRoleFromInstanceProfile","iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:TagUser","iam:UntagUser","iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:PassRole"],"Resource":"*"},
 {"Effect":"Allow","Action":["iam:Get*","iam:List*"],"Resource":"*"}]}`

// InlinePolicyJSON returns the formae-iam inline policy document.
// Exported for artifact-parity tests against the bootstrap templates.
func InlinePolicyJSON() string { return inlinePolicyJSON }

// ensurePosture set-reconciles the role's attached-managed and inline
// policy sets to the fixed posture. The order is chosen so an
// interruption never leaves the role below the posture: attach the
// managed policy if missing, put the inline document (unconditional,
// idempotent), then detach foreign managed and delete foreign inline
// policies. Permissions boundaries are the customer's and untouched.
func (a *AWS) ensurePosture(ctx context.Context) (detached, deletedInline []string, err error) {
	var attachedArns []string
	var marker *string
	for {
		page, err := a.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(a.roleName),
			Marker:   marker,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list attached role policies: %w", err)
		}
		for _, p := range page.AttachedPolicies {
			attachedArns = append(attachedArns, aws.ToString(p.PolicyArn))
		}
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}

	hasManaged := false
	for _, arn := range attachedArns {
		if arn == ManagedPolicyArn {
			hasManaged = true
		}
	}
	if !hasManaged {
		_, err := a.iam.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			RoleName:  aws.String(a.roleName),
			PolicyArn: aws.String(ManagedPolicyArn),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to attach the managed policy: %w", err)
		}
		a.logger.Info("attached: managed policy")
	}

	_, err = a.iam.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(a.roleName),
		PolicyName:     aws.String(InlinePolicyName),
		PolicyDocument: aws.String(inlinePolicyJSON),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to put the inline policy: %w", err)
	}

	for _, arn := range attachedArns {
		if arn == ManagedPolicyArn {
			continue
		}
		_, err := a.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  aws.String(a.roleName),
			PolicyArn: aws.String(arn),
		})
		if err != nil {
			return detached, deletedInline, fmt.Errorf("failed to detach a foreign managed policy: %w", err)
		}
		detached = append(detached, arn)
		a.logger.Info("detached: foreign managed policy")
	}

	var inlineNames []string
	marker = nil
	for {
		page, err := a.iam.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: aws.String(a.roleName),
			Marker:   marker,
		})
		if err != nil {
			return detached, deletedInline, fmt.Errorf("failed to list inline role policies: %w", err)
		}
		inlineNames = append(inlineNames, page.PolicyNames...)
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}

	for _, name := range inlineNames {
		if name == InlinePolicyName {
			continue
		}
		_, err := a.iam.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(a.roleName),
			PolicyName: aws.String(name),
		})
		if err != nil {
			return detached, deletedInline, fmt.Errorf("failed to delete a foreign inline policy: %w", err)
		}
		deletedInline = append(deletedInline, name)
		a.logger.Info("deleted: foreign inline policy")
	}

	return detached, deletedInline, nil
}

// deletePosture removes the posture's attachments so DeleteRole can
// succeed: IAM refuses to delete a role that still has attached or
// inline policies. Both removals tolerate not-found.
func (a *AWS) deletePosture(ctx context.Context) error {
	var noSuchEntityErr *types.NoSuchEntityException

	_, err := a.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String(a.roleName),
		PolicyArn: aws.String(ManagedPolicyArn),
	})
	if err != nil && !errors.As(err, &noSuchEntityErr) {
		return err
	}

	_, err = a.iam.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
		RoleName:   aws.String(a.roleName),
		PolicyName: aws.String(InlinePolicyName),
	})
	if err != nil && !errors.As(err, &noSuchEntityErr) {
		return err
	}

	a.logger.Info("deleted: connector role posture")

	return nil
}
