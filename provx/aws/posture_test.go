package aws

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func attachedPolicy(arn string) types.AttachedPolicy {
	return types.AttachedPolicy{PolicyArn: awssdk.String(arn)}
}

func TestInlinePolicyLiteral(t *testing.T) {
	var doc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Effect   string   `json:"Effect"`
			Action   []string `json:"Action"`
			Resource string   `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(InlinePolicyJSON()), &doc); err != nil {
		t.Fatalf("InlinePolicyJSON does not parse: %v", err)
	}
	if doc.Version != "2012-10-17" {
		t.Fatalf("Version = %q", doc.Version)
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("want exactly 2 statements, got %d", len(doc.Statement))
	}
	first := doc.Statement[0]
	for _, must := range []string{"iam:PassRole", "iam:CreateRole", "iam:UpdateAssumeRolePolicy"} {
		if !slices.Contains(first.Action, must) {
			t.Fatalf("statement[0] misses %s", must)
		}
	}
	if len(first.Action) != 38 {
		t.Fatalf("statement[0] has %d actions, want 38", len(first.Action))
	}
	if !reflect.DeepEqual(doc.Statement[1].Action, []string{"iam:Get*", "iam:List*"}) {
		t.Fatalf("statement[1] actions = %v", doc.Statement[1].Action)
	}
	if first.Resource != "*" || doc.Statement[1].Resource != "*" {
		t.Fatalf("resources = %q, %q, want *", first.Resource, doc.Statement[1].Resource)
	}
	if strings.Contains(InlinePolicyJSON(), "ssmmessages") {
		t.Fatal("the ECS-exec ssmmessages policy must not leak into the posture")
	}
}

func TestPostureFreshRole(t *testing.T) {
	attached := false
	put := false
	f := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{}, nil
		},
		attachRolePolicy: func(in *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
			if awssdk.ToString(in.PolicyArn) != ManagedPolicyArn {
				t.Fatalf("attached %q", awssdk.ToString(in.PolicyArn))
			}
			attached = true
			return &iam.AttachRolePolicyOutput{}, nil
		},
		putRolePolicy: func(in *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			if awssdk.ToString(in.PolicyName) != InlinePolicyName {
				t.Fatalf("put %q", awssdk.ToString(in.PolicyName))
			}
			if awssdk.ToString(in.PolicyDocument) != InlinePolicyJSON() {
				t.Fatalf("put document differs from InlinePolicyJSON")
			}
			put = true
			return &iam.PutRolePolicyOutput{}, nil
		},
		// detachRolePolicy and deleteRolePolicy nil: any call fails the test.
	}
	detached, deletedInline, err := newTestAWS(t, f).ensurePosture(context.Background())
	if err != nil || detached != nil || deletedInline != nil {
		t.Fatalf("detached=%v deleted=%v err=%v", detached, deletedInline, err)
	}
	if !attached || !put {
		t.Fatalf("attached=%v put=%v", attached, put)
	}
}

func TestPostureIdempotent(t *testing.T) {
	puts := 0
	f := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(ManagedPolicyArn)}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName}}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			puts++
			return &iam.PutRolePolicyOutput{}, nil
		},
		// attachRolePolicy nil: an attach would fail the test.
	}
	detached, deletedInline, err := newTestAWS(t, f).ensurePosture(context.Background())
	if err != nil || detached != nil || deletedInline != nil {
		t.Fatalf("detached=%v deleted=%v err=%v", detached, deletedInline, err)
	}
	if puts != 1 {
		t.Fatalf("putRolePolicy called %d times, want 1", puts)
	}
}

func TestPostureDetachesForeignManaged(t *testing.T) {
	const foreign = "arn:aws:iam::aws:policy/AdministratorAccess"
	var got []string
	f := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{
				attachedPolicy(ManagedPolicyArn), attachedPolicy(foreign),
			}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName}}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
		detachRolePolicy: func(in *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
			got = append(got, awssdk.ToString(in.PolicyArn))
			return &iam.DetachRolePolicyOutput{}, nil
		},
	}
	detached, _, err := newTestAWS(t, f).ensurePosture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{foreign}) || !reflect.DeepEqual(detached, []string{foreign}) {
		t.Fatalf("detach calls=%v detached=%v", got, detached)
	}
}

func TestPostureDeletesForeignInline(t *testing.T) {
	var got []string
	f := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(ManagedPolicyArn)}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName, "legacy"}}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
		deleteRolePolicy: func(in *iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
			got = append(got, awssdk.ToString(in.PolicyName))
			return &iam.DeleteRolePolicyOutput{}, nil
		},
	}
	_, deletedInline, err := newTestAWS(t, f).ensurePosture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"legacy"}) || !reflect.DeepEqual(deletedInline, []string{"legacy"}) {
		t.Fatalf("delete calls=%v deletedInline=%v", got, deletedInline)
	}
}

func TestPostureAttachBeforeDetachOrdering(t *testing.T) {
	const foreign = "arn:aws:iam::aws:policy/AdministratorAccess"
	f := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(foreign)}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName}}, nil
		},
		attachRolePolicy: func(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
			return &iam.AttachRolePolicyOutput{}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
		detachRolePolicy: func(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
			return &iam.DetachRolePolicyOutput{}, nil
		},
	}
	if _, _, err := newTestAWS(t, f).ensurePosture(context.Background()); err != nil {
		t.Fatal(err)
	}
	attachAt := slices.Index(f.calls, "AttachRolePolicy")
	detachAt := slices.Index(f.calls, "DetachRolePolicy")
	if attachAt == -1 || detachAt == -1 || attachAt > detachAt {
		t.Fatalf("attach must precede detach, calls=%v", f.calls)
	}
}

func TestPostureInterruptedAfterAttachFailsThenHeals(t *testing.T) {
	// Run 1: fresh role, attach succeeds, PutRolePolicy fails.
	boom := errors.New("put failed")
	run1 := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{}, nil
		},
		attachRolePolicy: func(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
			return &iam.AttachRolePolicyOutput{}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return nil, boom
		},
	}
	if _, _, err := newTestAWS(t, run1).ensurePosture(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("run 1 must surface the put failure, got %v", err)
	}

	// Run 2 against the state run 1 left behind: managed attached, no inline.
	run2 := &fakeIAM{t: t,
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(ManagedPolicyArn)}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
	}
	detached, deletedInline, err := newTestAWS(t, run2).ensurePosture(context.Background())
	if err != nil || detached != nil || deletedInline != nil {
		t.Fatalf("run 2 must converge cleanly: detached=%v deleted=%v err=%v", detached, deletedInline, err)
	}
}

func TestPostureListPagination(t *testing.T) {
	const foreignManaged = "arn:aws:iam::aws:policy/AdministratorAccess"
	attachedPage := 0
	inlinePage := 0
	var detach, del []string
	f := &fakeIAM{t: t,
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
				return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(foreignManaged)}}, nil
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
				return &iam.ListRolePoliciesOutput{PolicyNames: []string{"legacy"}}, nil
			default:
				t.Fatalf("unexpected inline page %d", inlinePage)
				return nil, nil
			}
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
		detachRolePolicy: func(in *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
			detach = append(detach, awssdk.ToString(in.PolicyArn))
			return &iam.DetachRolePolicyOutput{}, nil
		},
		deleteRolePolicy: func(in *iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
			del = append(del, awssdk.ToString(in.PolicyName))
			return &iam.DeleteRolePolicyOutput{}, nil
		},
	}
	detached, deletedInline, err := newTestAWS(t, f).ensurePosture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detach, []string{foreignManaged}) || !reflect.DeepEqual(detached, []string{foreignManaged}) {
		t.Fatalf("foreign managed on page 2 must be detached: %v / %v", detach, detached)
	}
	if !reflect.DeepEqual(del, []string{"legacy"}) || !reflect.DeepEqual(deletedInline, []string{"legacy"}) {
		t.Fatalf("foreign inline on page 2 must be deleted: %v / %v", del, deletedInline)
	}
}

func TestPostureErrorsCarryNoSecrets(t *testing.T) {
	// The posture path handles no credentials; the subject stands in for
	// sensitive strings and must never appear in an error message.
	const subject = "fai:t/i"
	boom := errors.New("sdk failure")
	okAttachedList := func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
		return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{
			attachedPolicy(ManagedPolicyArn), attachedPolicy("arn:aws:iam::aws:policy/AdministratorAccess"),
		}}, nil
	}
	okInlineList := func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
		return &iam.ListRolePoliciesOutput{PolicyNames: []string{"legacy"}}, nil
	}
	okPut := func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
		return &iam.PutRolePolicyOutput{}, nil
	}
	okDetach := func(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
		return &iam.DetachRolePolicyOutput{}, nil
	}
	cases := map[string]*fakeIAM{
		"list attached fails": {
			listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
				return nil, boom
			},
		},
		"attach fails": {
			listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
				return &iam.ListAttachedRolePoliciesOutput{}, nil
			},
			attachRolePolicy: func(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
				return nil, boom
			},
		},
		"put fails": {
			listAttachedRolePolicies: okAttachedList,
			putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
				return nil, boom
			},
		},
		"detach fails": {
			listAttachedRolePolicies: okAttachedList,
			putRolePolicy:            okPut,
			detachRolePolicy: func(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
				return nil, boom
			},
		},
		"list inline fails": {
			listAttachedRolePolicies: okAttachedList,
			putRolePolicy:            okPut,
			detachRolePolicy:         okDetach,
			listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
				return nil, boom
			},
		},
		"delete inline fails": {
			listAttachedRolePolicies: okAttachedList,
			putRolePolicy:            okPut,
			detachRolePolicy:         okDetach,
			listRolePolicies:         okInlineList,
			deleteRolePolicy: func(*iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
				return nil, boom
			},
		},
	}
	for name, f := range cases {
		f.t = t
		_, _, err := newTestAWS(t, f).ensurePosture(context.Background())
		if err == nil {
			t.Fatalf("%s: want error", name)
		}
		if strings.Contains(err.Error(), subject) {
			t.Fatalf("%s: error leaks the subject: %v", name, err)
		}
	}
}
