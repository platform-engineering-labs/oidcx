package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/platform-engineering-labs/oidcx"
)

type Config struct {
	RoleARN     string
	Region      string
	SessionName string
}

type TokenRetriever struct {
	client oidcx.Client
	ctx    context.Context
}

func (t TokenRetriever) GetIdentityToken() ([]byte, error) {
	tok, err := t.client.Token(t.ctx)
	if err != nil {
		return nil, err
	}
	return []byte(tok), nil
}

func Credentials(ctx context.Context, client oidcx.Client, cfg *Config) (aws.CredentialsProvider, error) {
	// AssumeRoleWithWebIdentity is unauthenticated: the JWT is the credential.
	// Anonymous credentials stop the SDK from hunting for a credential chain and
	// failing before it ever reaches STS.
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}

	provider := stscreds.NewWebIdentityRoleProvider(
		sts.NewFromConfig(awsCfg),
		cfg.RoleARN,
		TokenRetriever{client: client, ctx: ctx},
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = cfg.SessionName
		},
	)

	// CredentialsCache holds the STS response and refreshes it (re-minting the
	// OIDC token) shortly before expiry.
	return aws.NewCredentialsCache(provider), nil
}
