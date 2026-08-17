package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/platform-engineering-labs/oox/provx"
)

var ConnectProvider = connectProvider{}

type connectProvider struct{}

func (connectProvider) Arn(accountId string) string {
	return fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountId, provx.Endpoint)
}

func (connectProvider) Exists(ctx context.Context, awsProv *AWS) (bool, error) {
	_, err := awsProv.client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(ConnectProvider.Arn(awsProv.accountId)),
	})

	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error fetching OIDC provider: %w", err)
	}

	return true, nil
}

func (connectProvider) Create(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.client.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
		Url: aws.String(fmt.Sprintf("https://%s", provx.Endpoint)),
		ClientIDList: []string{
			"sts.amazonaws.com",
		},
	})

	if err != nil {
		return fmt.Errorf("create openId connect provider failed: %v", err)
	}

	awsProv.Info("created OpenID connect provider successfully")

	return nil
}

func (connectProvider) Delete(ctx context.Context, awsProv *AWS) {
	_, err := awsProv.client.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(ConnectProvider.Arn(awsProv.accountId)),
	})
	if err != nil {
		awsProv.Error("failed to delete role: %v", err)
	} else {
		awsProv.Info("deleted openid connect provider")
	}
}
