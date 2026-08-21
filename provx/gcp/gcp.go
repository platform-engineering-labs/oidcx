package gcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/platform-engineering-labs/oox/provx"
	"github.com/platform-engineering-labs/oox/provx/gcp/provider"
)

type GCP struct {
	*slog.Logger

	client         *provider.Client
	project        string
	tenantId       string
	installationId string
}

func New(logger *slog.Logger, project, tenantId, installationId string) (*GCP, error) {
	client, err := provider.NewClient(context.Background())
	if err != nil {
		return nil, err
	}

	return &GCP{
		Logger:         logger,
		client:         client,
		project:        project,
		tenantId:       tenantId,
		installationId: installationId,
	}, nil
}

func (gcp *GCP) Create(ctx context.Context) error {
	pool, oidc, binding, err := gcp.spec(ctx)
	if err != nil {
		return err
	}

	_, err = gcp.client.EnsurePool(ctx, *pool)
	if err != nil {
		return err
	}

	_, err = gcp.client.EnsureOIDCProvider(ctx, *pool, *oidc)
	if err != nil {
		return err
	}

	err = gcp.client.EnsureProjectBinding(ctx, gcp.project, *binding)
	if err != nil {
		return err
	}

	return nil
}

func (gcp *GCP) Delete(ctx context.Context) error {
	pool, oidc, binding, err := gcp.spec(ctx)
	if err != nil {
		return err
	}

	err = gcp.client.RemoveProjectBinding(ctx, gcp.project, *binding)
	if err != nil {
		return err
	}

	err = gcp.client.DeleteOIDCProvider(ctx, *pool, oidc.ProviderID)
	if err != nil {
		return err
	}

	err = gcp.client.DeletePool(ctx, *pool)
	if err != nil {
		return err
	}

	return nil
}

func (gcp *GCP) spec(ctx context.Context) (*provider.PoolSpec, *provider.OIDCProviderSpec, *provider.Binding, error) {
	pool := &provider.PoolSpec{
		Project:     gcp.project,
		PoolID:      "formae-ai",
		DisplayName: "formae AI Cloud",
		Description: "Federated identities from formae AI Cloud",
	}

	oidcProvider := &provider.OIDCProviderSpec{
		ProviderID:  "formae-ai",
		DisplayName: "formae ai Cloud OIDC",
		IssuerURI:   fmt.Sprintf("https://%s", provx.Endpoint),
		AttributeMapping: map[string]string{
			"google.subject": "assertion.sub",
		},
		AttributeCondition: fmt.Sprintf(`google.subject == "%s"`, provx.Subject(gcp.tenantId, gcp.installationId)),
	}

	member, err := gcp.client.SubjectPrincipal(ctx, *pool, provx.Subject(gcp.tenantId, gcp.installationId))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get subject principal: %w", err)
	}
	binding := &provider.Binding{
		Role:   "roles/project.Owner",
		Member: member,
	}

	return pool, oidcProvider, binding, nil
}
