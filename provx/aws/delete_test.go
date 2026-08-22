package aws

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func ownedTags() *iam.ListRoleTagsOutput {
	return &iam.ListRoleTagsOutput{Tags: []types.Tag{
		tag("formae-ai:owner", "provx"),
		tag("formae-ai:subject", "fai:t/i"),
	}}
}

func TestDeleteRefusesForeignOwner(t *testing.T) {
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{tag("formae-ai:owner", "cloudformation")}}, nil
		},
		// Every mutation field nil: any destructive call fails the test.
	}
	err := newTestAWS(t, f).Delete(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
	if collision.Owner != "cloudformation" {
		t.Fatalf("Owner = %q", collision.Owner)
	}
	if !reflect.DeepEqual(f.calls, []string{"ListRoleTags"}) {
		t.Fatalf("a refused delete must only read tags, calls=%v", f.calls)
	}
}

func TestDeleteRefusesUntaggedRole(t *testing.T) {
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{}, nil
		},
	}
	err := newTestAWS(t, f).Delete(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
	if collision.Owner != "" {
		t.Fatalf("Owner = %q, want empty", collision.Owner)
	}
	if !reflect.DeepEqual(f.calls, []string{"ListRoleTags"}) {
		t.Fatalf("a refused delete must only read tags, calls=%v", f.calls)
	}
}

func TestDeleteRefusesSubjectMismatch(t *testing.T) {
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{
				tag("formae-ai:owner", "provx"),
				tag("formae-ai:subject", "fai:other/x"),
			}}, nil
		},
	}
	err := newTestAWS(t, f).Delete(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
	if collision.SubjectFound != "fai:other/x" || collision.SubjectWanted != "fai:t/i" {
		t.Fatalf("subjects = found %q wanted %q", collision.SubjectFound, collision.SubjectWanted)
	}
	if !reflect.DeepEqual(f.calls, []string{"ListRoleTags"}) {
		t.Fatalf("a refused delete must only read tags, calls=%v", f.calls)
	}
}

func TestDeleteAlreadyDeletedRoleStillDeletesProvider(t *testing.T) {
	providerDeleted := false
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return nil, &types.NoSuchEntityException{}
		},
		deleteOIDCProvider: func(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error) {
			providerDeleted = true
			return &iam.DeleteOpenIDConnectProviderOutput{}, nil
		},
		// All role mutation fields nil: touching the gone role fails the test.
	}
	if err := newTestAWS(t, f).Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !providerDeleted {
		t.Fatal("provider must still be deleted when the role is already gone")
	}
}

func TestDeleteLegacyRoleDetachesEverythingThenDeletes(t *testing.T) {
	const legacyManaged = "arn:aws:iam::aws:policy/AdministratorAccess"
	var detach, del []string
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return ownedTags(), nil
		},
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{
				attachedPolicy(ManagedPolicyArn), attachedPolicy(legacyManaged),
			}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName, "legacy"}}, nil
		},
		detachRolePolicy: func(in *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
			detach = append(detach, awssdk.ToString(in.PolicyArn))
			return &iam.DetachRolePolicyOutput{}, nil
		},
		deleteRolePolicy: func(in *iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
			del = append(del, awssdk.ToString(in.PolicyName))
			return &iam.DeleteRolePolicyOutput{}, nil
		},
		deleteRole: func(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
			return &iam.DeleteRoleOutput{}, nil
		},
		deleteOIDCProvider: func(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error) {
			return &iam.DeleteOpenIDConnectProviderOutput{}, nil
		},
	}
	if err := newTestAWS(t, f).Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detach, []string{ManagedPolicyArn, legacyManaged}) {
		t.Fatalf("every attached managed policy must be detached, got %v", detach)
	}
	if !reflect.DeepEqual(del, []string{InlinePolicyName, "legacy"}) {
		t.Fatalf("every inline policy must be deleted, got %v", del)
	}
	deleteAt := slices.Index(f.calls, "DeleteRole")
	lastDetach := -1
	for i, c := range f.calls {
		if c == "DetachRolePolicy" {
			lastDetach = i
		}
	}
	if deleteAt == -1 || deleteAt < lastDetach {
		t.Fatalf("DeleteRole must follow every detach, calls=%v", f.calls)
	}
}

func TestDeleteEnumerationsPaginated(t *testing.T) {
	const pagedManaged = "arn:aws:iam::111122223333:policy/second-page"
	attachedPage := 0
	inlinePage := 0
	var detach, del []string
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return ownedTags(), nil
		},
		listAttachedRolePolicies: func(in *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			attachedPage++
			switch attachedPage {
			case 1:
				return &iam.ListAttachedRolePoliciesOutput{
					IsTruncated:      true,
					Marker:           awssdk.String("am"),
					AttachedPolicies: []types.AttachedPolicy{attachedPolicy(ManagedPolicyArn)},
				}, nil
			case 2:
				if awssdk.ToString(in.Marker) != "am" {
					t.Fatalf("attached page 2 Marker = %q", awssdk.ToString(in.Marker))
				}
				return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(pagedManaged)}}, nil
			default:
				t.Fatalf("unexpected attached page %d", attachedPage)
				return nil, nil
			}
		},
		listRolePolicies: func(in *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			inlinePage++
			switch inlinePage {
			case 1:
				return &iam.ListRolePoliciesOutput{
					IsTruncated: true,
					Marker:      awssdk.String("im"),
					PolicyNames: []string{InlinePolicyName},
				}, nil
			case 2:
				if awssdk.ToString(in.Marker) != "im" {
					t.Fatalf("inline page 2 Marker = %q", awssdk.ToString(in.Marker))
				}
				return &iam.ListRolePoliciesOutput{PolicyNames: []string{"second-page"}}, nil
			default:
				t.Fatalf("unexpected inline page %d", inlinePage)
				return nil, nil
			}
		},
		detachRolePolicy: func(in *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
			detach = append(detach, awssdk.ToString(in.PolicyArn))
			return &iam.DetachRolePolicyOutput{}, nil
		},
		deleteRolePolicy: func(in *iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
			del = append(del, awssdk.ToString(in.PolicyName))
			return &iam.DeleteRolePolicyOutput{}, nil
		},
		deleteRole: func(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
			return &iam.DeleteRoleOutput{}, nil
		},
		deleteOIDCProvider: func(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error) {
			return &iam.DeleteOpenIDConnectProviderOutput{}, nil
		},
	}
	if err := newTestAWS(t, f).Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detach, []string{ManagedPolicyArn, pagedManaged}) {
		t.Fatalf("attachments on page 2 must be detached, got %v", detach)
	}
	if !reflect.DeepEqual(del, []string{InlinePolicyName, "second-page"}) {
		t.Fatalf("inline policies on page 2 must be deleted, got %v", del)
	}
}

func TestDeleteToleratesConcurrentlyRemovedAttachments(t *testing.T) {
	f := &fakeIAM{t: t,
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return ownedTags(), nil
		},
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(ManagedPolicyArn)}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName}}, nil
		},
		detachRolePolicy: func(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
			return nil, &types.NoSuchEntityException{}
		},
		deleteRolePolicy: func(*iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
			return nil, &types.NoSuchEntityException{}
		},
		deleteRole: func(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
			return nil, &types.NoSuchEntityException{}
		},
		deleteOIDCProvider: func(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error) {
			return nil, &types.NoSuchEntityException{}
		},
	}
	if err := newTestAWS(t, f).Delete(context.Background()); err != nil {
		t.Fatalf("not-found during teardown must be tolerated, got %v", err)
	}
}
