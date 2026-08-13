package oidcx

import "context"

type Client interface {
	Token(ctx context.Context, audience string) (string, error)
}
