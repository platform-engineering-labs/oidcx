package aws

import "fmt"

// AccountMismatchError: the credentials authenticate to a different
// account than the one the caller stated. Nothing was mutated.
type AccountMismatchError struct{ Expected, Actual string }

func (e *AccountMismatchError) Error() string {
	return fmt.Sprintf("credentials belong to account %s, not the stated account %s", e.Actual, e.Expected)
}

// RoleCollisionError: a role with the requested name exists but is not
// safely ours to modify - no ownership tags, a foreign owner, or an
// ownership subject differing from the requested one.
type RoleCollisionError struct {
	RoleName, Owner             string
	SubjectWanted, SubjectFound string
}

func (e *RoleCollisionError) Error() string {
	switch {
	case e.Owner == "":
		return fmt.Sprintf("role %s exists but carries no ownership tags; refusing to modify it", e.RoleName)
	case e.SubjectWanted != "" && e.SubjectWanted != e.SubjectFound:
		return fmt.Sprintf("role %s is owned for subject %s, not the requested %s; refusing to modify it", e.RoleName, e.SubjectFound, e.SubjectWanted)
	default:
		return fmt.Sprintf("role %s is owned by %s; refusing to modify it", e.RoleName, e.Owner)
	}
}

// ProviderConflictError: the existing OIDC provider's configuration is
// not something this provisioner can safely converge. Cause, when set,
// carries the underlying SDK error.
type ProviderConflictError struct {
	Reason string
	Cause  error
}

func (e *ProviderConflictError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("existing OIDC provider conflict: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("existing OIDC provider conflict: %s", e.Reason)
}

func (e *ProviderConflictError) Unwrap() error { return e.Cause }
