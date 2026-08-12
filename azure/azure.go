package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/platform-engineering-labs/oidcx"
)

const Audience = "api://AzureADTokenExchange"

// AzureConfig describes the Entra workload identity federation target.
type Config struct {
	TenantID string

	// ClientID is the app registration or user-assigned managed identity that
	// carries the federated identity credential.
	ClientID string

	Scopes []string
}

func (c Config) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return []string{"https://management.azure.com/.default"}
}

// Credential returns an azidentity credential.
//
// Entra's flow differs from AWS and GCP: there is no separate exchange endpoint.
// The token is presented as the client assertion in an ordinary client
// credentials grant, standing in for the client secret the app registration
// would otherwise need. The callback is invoked on every refresh.
func Credential(client oidcx.Client, cfg Config) (*azidentity.ClientAssertionCredential, error) {
	return azidentity.NewClientAssertionCredential(
		cfg.TenantID,
		cfg.ClientID,
		func(ctx context.Context) (string, error) {
			return client.Token(ctx, Audience)
		},
		nil,
	)
}
