package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

var ConnectProvider = connectProvider{}

type connectProvider struct{}

func (connectProvider) Arn(awsProv *AWS) string {
	return fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", awsProv.accountID, awsProv.issuer.Host())
}

func (connectProvider) Create(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.iam.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
		Url: aws.String(awsProv.issuer.URL()),
		ClientIDList: []string{
			"sts.amazonaws.com",
		},
	})
	if err != nil {
		var alreadyExistsErr *types.EntityAlreadyExistsException
		if errors.As(err, &alreadyExistsErr) {
			awsProv.logger.Info("exists: oidc connect provider")
			return nil
		}

		return fmt.Errorf("create openId connect provider failed: %v", err)
	}

	awsProv.logger.Info("created: oidc connect provider")

	return nil
}

func (connectProvider) Delete(ctx context.Context, awsProv *AWS) error {
	_, err := awsProv.iam.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(ConnectProvider.Arn(awsProv)),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			awsProv.logger.Info("already deleted: oidc connect provider")
			return nil
		} else {
			return err
		}
	}

	awsProv.logger.Info("deleted: oidc connect provider")

	return nil
}
