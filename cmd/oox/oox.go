package main

import (
	"context"
	"oox/cli"
	"os"

	"charm.land/fang/v2"
	"github.com/platform-engineering-labs/pelx/theme"
)

func main() {
	if err := fang.Execute(
		context.Background(),
		cli.Root,
		fang.WithoutVersion(),
		fang.WithColorSchemeFunc(theme.FangTheme),
	); err != nil {
		os.Exit(1)
	}
}
