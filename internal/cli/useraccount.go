package cli

import (
	"github.com/spf13/cobra"
)

var UserCmd = &cobra.Command{
	Use:     "user [username]",
	Short:   "Show Kubernetes access for user",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		opts, err := ValidateCommonFlags(cmd, args)
		if err != nil {
			return err
		}
		return RunAccessCheck(cmd, args, false, opts)
	},
}

func init() {
	addCommonFlags(UserCmd)
}
