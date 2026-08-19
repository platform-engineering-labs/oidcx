package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/platform-engineering-labs/oox/provx/aws"
	"github.com/spf13/cobra"
)

func init() {
	ProvisionAWS.AddCommand(ProvisionAWSCreate)
	ProvisionAWS.AddCommand(ProvisionAWSDelete)

	ProvisionAWSCreate.Flags().String("account", "", "AWS account id")
	ProvisionAWSCreate.Flags().String("access-key", "", "AWS access key id")
	ProvisionAWSCreate.Flags().String("secret-key", "", "AWS access key secret")

	ProvisionAWSDelete.Flags().String("account", "", "AWS account id")
	ProvisionAWSDelete.Flags().String("access-key", "", "AWS access key id")
	ProvisionAWSDelete.Flags().String("secret-key", "", "AWS access key secret")
}

var ProvisionAWS = &cobra.Command{
	Use:   "aws",
	Short: "provision an oidc connector to AWS",
}

var ProvisionAWSCreate = &cobra.Command{
	Use:   "create [tenantId] [installationId]",
	Short: "provision oidc connector to AWS",

	RunE: func(cmd *cobra.Command, args []string) error {
		account, _ := cmd.Flags().GetString("account")
		accessKey, _ := cmd.Flags().GetString("access-key")
		secretKey, _ := cmd.Flags().GetString("secret-key")

		if accessKey == "" || secretKey == "" {
			return fmt.Errorf("must provide access key and secret key")
		}

		tenantId := cmd.Flags().Arg(0)
		if tenantId == "" {
			return fmt.Errorf("must provide tenant id")
		}

		installationId := cmd.Flags().Arg(1)
		if installationId == "" {
			return fmt.Errorf("must provide installation id")
		}

		prov, err := aws.New(slog.New(Logger), credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""), "", account, tenantId, installationId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		err = prov.Create(ctx)
		if err != nil {
			return err
		}

		return nil
	},
}

var ProvisionAWSDelete = &cobra.Command{
	Use:   "delete [tenantId] [installationId]",
	Short: "de-provision oidc connector to AWS",

	RunE: func(cmd *cobra.Command, args []string) error {
		account, _ := cmd.Flags().GetString("account")
		accessKey, _ := cmd.Flags().GetString("access-key")
		secretKey, _ := cmd.Flags().GetString("secret-key")

		if accessKey == "" || secretKey == "" {
			return fmt.Errorf("must provide access key and secret key")
		}

		tenantId := cmd.Flags().Arg(0)
		if tenantId == "" {
			return fmt.Errorf("must provide tenant id")
		}

		installationId := cmd.Flags().Arg(1)
		if installationId == "" {
			return fmt.Errorf("must provide installation id")
		}

		prov, err := aws.New(slog.New(Logger), credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""), "", account, tenantId, installationId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		err = prov.Delete(ctx)
		if err != nil {
			return err
		}

		return nil
	},
}
