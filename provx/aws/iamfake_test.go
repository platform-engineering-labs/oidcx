package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// fakeIAM implements iamAPI with one function field per method. A method
// whose field is nil fails the test ("unexpected call"); otherwise the
// call is recorded in calls and delegated to the field.
type fakeIAM struct {
	t     *testing.T
	calls []string

	createOIDCProvider       func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error)
	getOIDCProvider          func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error)
	addClientID              func(*iam.AddClientIDToOpenIDConnectProviderInput) (*iam.AddClientIDToOpenIDConnectProviderOutput, error)
	deleteOIDCProvider       func(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error)
	createRole               func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error)
	getRole                  func(*iam.GetRoleInput) (*iam.GetRoleOutput, error)
	deleteRole               func(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error)
	listRoleTags             func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error)
	updateAssumeRolePolicy   func(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error)
	attachRolePolicy         func(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error)
	detachRolePolicy         func(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error)
	listAttachedRolePolicies func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	putRolePolicy            func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error)
	listRolePolicies         func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error)
	deleteRolePolicy         func(*iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error)
}

func (f *fakeIAM) record(name string) {
	f.calls = append(f.calls, name)
}

func (f *fakeIAM) CreateOpenIDConnectProvider(_ context.Context, in *iam.CreateOpenIDConnectProviderInput, _ ...func(*iam.Options)) (*iam.CreateOpenIDConnectProviderOutput, error) {
	f.t.Helper()
	if f.createOIDCProvider == nil {
		f.t.Fatal("unexpected call CreateOpenIDConnectProvider")
	}
	f.record("CreateOpenIDConnectProvider")
	return f.createOIDCProvider(in)
}

func (f *fakeIAM) GetOpenIDConnectProvider(_ context.Context, in *iam.GetOpenIDConnectProviderInput, _ ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error) {
	f.t.Helper()
	if f.getOIDCProvider == nil {
		f.t.Fatal("unexpected call GetOpenIDConnectProvider")
	}
	f.record("GetOpenIDConnectProvider")
	return f.getOIDCProvider(in)
}

func (f *fakeIAM) AddClientIDToOpenIDConnectProvider(_ context.Context, in *iam.AddClientIDToOpenIDConnectProviderInput, _ ...func(*iam.Options)) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
	f.t.Helper()
	if f.addClientID == nil {
		f.t.Fatal("unexpected call AddClientIDToOpenIDConnectProvider")
	}
	f.record("AddClientIDToOpenIDConnectProvider")
	return f.addClientID(in)
}

func (f *fakeIAM) DeleteOpenIDConnectProvider(_ context.Context, in *iam.DeleteOpenIDConnectProviderInput, _ ...func(*iam.Options)) (*iam.DeleteOpenIDConnectProviderOutput, error) {
	f.t.Helper()
	if f.deleteOIDCProvider == nil {
		f.t.Fatal("unexpected call DeleteOpenIDConnectProvider")
	}
	f.record("DeleteOpenIDConnectProvider")
	return f.deleteOIDCProvider(in)
}

func (f *fakeIAM) CreateRole(_ context.Context, in *iam.CreateRoleInput, _ ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	f.t.Helper()
	if f.createRole == nil {
		f.t.Fatal("unexpected call CreateRole")
	}
	f.record("CreateRole")
	return f.createRole(in)
}

func (f *fakeIAM) GetRole(_ context.Context, in *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	f.t.Helper()
	if f.getRole == nil {
		f.t.Fatal("unexpected call GetRole")
	}
	f.record("GetRole")
	return f.getRole(in)
}

func (f *fakeIAM) DeleteRole(_ context.Context, in *iam.DeleteRoleInput, _ ...func(*iam.Options)) (*iam.DeleteRoleOutput, error) {
	f.t.Helper()
	if f.deleteRole == nil {
		f.t.Fatal("unexpected call DeleteRole")
	}
	f.record("DeleteRole")
	return f.deleteRole(in)
}

func (f *fakeIAM) ListRoleTags(_ context.Context, in *iam.ListRoleTagsInput, _ ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	f.t.Helper()
	if f.listRoleTags == nil {
		f.t.Fatal("unexpected call ListRoleTags")
	}
	f.record("ListRoleTags")
	return f.listRoleTags(in)
}

func (f *fakeIAM) UpdateAssumeRolePolicy(_ context.Context, in *iam.UpdateAssumeRolePolicyInput, _ ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error) {
	f.t.Helper()
	if f.updateAssumeRolePolicy == nil {
		f.t.Fatal("unexpected call UpdateAssumeRolePolicy")
	}
	f.record("UpdateAssumeRolePolicy")
	return f.updateAssumeRolePolicy(in)
}

func (f *fakeIAM) AttachRolePolicy(_ context.Context, in *iam.AttachRolePolicyInput, _ ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error) {
	f.t.Helper()
	if f.attachRolePolicy == nil {
		f.t.Fatal("unexpected call AttachRolePolicy")
	}
	f.record("AttachRolePolicy")
	return f.attachRolePolicy(in)
}

func (f *fakeIAM) DetachRolePolicy(_ context.Context, in *iam.DetachRolePolicyInput, _ ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error) {
	f.t.Helper()
	if f.detachRolePolicy == nil {
		f.t.Fatal("unexpected call DetachRolePolicy")
	}
	f.record("DetachRolePolicy")
	return f.detachRolePolicy(in)
}

func (f *fakeIAM) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	f.t.Helper()
	if f.listAttachedRolePolicies == nil {
		f.t.Fatal("unexpected call ListAttachedRolePolicies")
	}
	f.record("ListAttachedRolePolicies")
	return f.listAttachedRolePolicies(in)
}

func (f *fakeIAM) PutRolePolicy(_ context.Context, in *iam.PutRolePolicyInput, _ ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error) {
	f.t.Helper()
	if f.putRolePolicy == nil {
		f.t.Fatal("unexpected call PutRolePolicy")
	}
	f.record("PutRolePolicy")
	return f.putRolePolicy(in)
}

func (f *fakeIAM) ListRolePolicies(_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	f.t.Helper()
	if f.listRolePolicies == nil {
		f.t.Fatal("unexpected call ListRolePolicies")
	}
	f.record("ListRolePolicies")
	return f.listRolePolicies(in)
}

func (f *fakeIAM) DeleteRolePolicy(_ context.Context, in *iam.DeleteRolePolicyInput, _ ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error) {
	f.t.Helper()
	if f.deleteRolePolicy == nil {
		f.t.Fatal("unexpected call DeleteRolePolicy")
	}
	f.record("DeleteRolePolicy")
	return f.deleteRolePolicy(in)
}
