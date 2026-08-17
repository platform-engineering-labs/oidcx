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

func (connectProvider) Create(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.client.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
		Url: aws.String(fmt.Sprintf("https://%s", provx.Endpoint)),
		ClientIDList: []string{
			"sts.amazonaws.com",
		},
	})
	if err != nil {
		var alreadyExistsErr *types.EntityAlreadyExistsException
		if errors.As(err, &alreadyExistsErr) {
			awsProv.Info("exists: oidc connect provider")
			return nil
		}

		return fmt.Errorf("create openId connect provider failed: %v", err)
	}

	awsProv.Info("created: oidc connect provider")

	return nil
}

func (connectProvider) Delete(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.client.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(ConnectProvider.Arn(awsProv.accountId)),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			awsProv.Info("already deleted: oidc connect provider")
			return nil
		} else {
			return err
		}
	}

	awsProv.Info("deleted: oidc connect provider")

	return nil
}
