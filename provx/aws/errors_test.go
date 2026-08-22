package aws

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAccountMismatchError(t *testing.T) {
	var target *AccountMismatchError
	err := fmt.Errorf("wrapped: %w", &AccountMismatchError{Expected: "111122223333", Actual: "444455556666"})
	if !errors.As(err, &target) {
		t.Fatal("errors.As failed")
	}
	if !strings.Contains(err.Error(), "111122223333") || !strings.Contains(err.Error(), "444455556666") {
		t.Fatalf("message must name both accounts: %v", err)
	}
}

func TestRoleCollisionErrorVariants(t *testing.T) {
	noTags := &RoleCollisionError{RoleName: "fai-x"}
	if !strings.Contains(noTags.Error(), "no ownership tags") {
		t.Fatalf("no-tags message: %v", noTags)
	}
	foreign := &RoleCollisionError{RoleName: "fai-x", Owner: "cloudformation"}
	if !strings.Contains(foreign.Error(), "cloudformation") {
		t.Fatalf("foreign-owner message: %v", foreign)
	}
	subj := &RoleCollisionError{RoleName: "fai-x", Owner: "provx", SubjectWanted: "fai:a/b", SubjectFound: "fai:c/d"}
	if !strings.Contains(subj.Error(), "fai:a/b") || !strings.Contains(subj.Error(), "fai:c/d") {
		t.Fatalf("subject-mismatch message must name both subjects: %v", subj)
	}
}

func TestProviderConflictErrorUnwraps(t *testing.T) {
	cause := errors.New("sdk boom")
	err := fmt.Errorf("w: %w", &ProviderConflictError{Reason: "get failed", Cause: cause})
	var target *ProviderConflictError
	if !errors.As(err, &target) {
		t.Fatal("errors.As failed")
	}
	if !errors.Is(err, cause) {
		t.Fatal("cause must stay discoverable through Unwrap")
	}
}
