package oidcx

import "context"

type Client interface {
	Token(ctx context.Context) (string, error)
}
