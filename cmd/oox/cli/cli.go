package cli

import "github.com/spf13/cobra"

func init() {
	Root.AddCommand(Provision)
}

var Root = &cobra.Command{
	Use:   "oox",
	Short: "oox - library test command",
}
