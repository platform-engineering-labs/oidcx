package provx

import "fmt"

const Endpoint = "oidc.cloud.formae.ai"

func Subject(tenantId, installationId string) string {
	return fmt.Sprintf("fai:%s/%s", tenantId, installationId)
}

func SubjectIdentifier(tenantId, installationId string) string {
	return fmt.Sprintf("fai-%s-%s", tenantId, installationId)
}
