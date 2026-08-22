package gcp

/* Note: does not support SA impersonation, only a handful of services require this
   will add support if necessary
*/

import (
	"context"
	"fmt"

	"github.com/platform-engineering-labs/oox/oidcx"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	AudienceTpl     = "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s"
	PrincipalTpl    = "principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/%s"
	PrincipalSetTpl = "principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.%s/%s"
)

type Config struct {
	// ProjectNumber is the numeric project number, not the project ID.
	ProjectNumber string
	PoolID        string
	ProviderID    string

	scopes []string
}

func NewConfig(scopes []string) Config {
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	return Config{scopes: scopes}
}

func (c Config) Scopes() []string {
	return c.scopes
}

// Audience is the full provider resource name. GCP expects this as the audience
// of the token exchange request, and by default also requires it in the incoming
// token's own aud claim.
func (c Config) Audience() string {
	return fmt.Sprintf(
		AudienceTpl,
		c.ProjectNumber, c.PoolID, c.ProviderID)
}

// Principal is the IAM identifier for one federated subject, for use in
// role bindings.
func (c Config) Principal(subject string) string {
	return fmt.Sprintf(
		PrincipalTpl,
		c.ProjectNumber, c.PoolID, subject)
}

// PrincipalSet is the IAM identifier for every subject sharing a mapped
// attribute value. This has no AWS equivalent: it is how you bind a role to a
// whole class of workloads rather than one at a time.
func (c Config) PrincipalSet(attribute, value string) string {
	return fmt.Sprintf(
		PrincipalSetTpl,
		c.ProjectNumber, c.PoolID, attribute, value)
}

// SubjectTokenSupplier feeds tokens to Google's external account
// machinery. It is the direct analogue of stscreds.IdentityTokenRetriever on the
// AWS side, and is called again on every refresh.
type SubjectTokenSupplier struct {
	client oidcx.Client
}

func (s SubjectTokenSupplier) SubjectToken(ctx context.Context, opts externalaccount.SupplierOptions) (string, error) {
	return s.client.Token(ctx, opts.Audience)
}

// TokenSource returns an oauth2.TokenSource that trades tokens for
// Google credentials and refreshes them automatically. Pass it to any Google
// client library with option.WithTokenSource.
func TokenSource(ctx context.Context, client oidcx.Client, cfg Config) (oauth2.TokenSource, error) {
	conf := externalaccount.Config{
		Audience:             cfg.Audience(),
		SubjectTokenType:     "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:             "https://sts.googleapis.com/v1/token",
		SubjectTokenSupplier: SubjectTokenSupplier{client: client},
		Scopes:               cfg.Scopes(),
	}

	return externalaccount.NewTokenSource(ctx, conf)
}
