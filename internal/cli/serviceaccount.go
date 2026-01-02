package cli

import (
	"github.com/spf13/cobra"
)

var SaCmd = &cobra.Command{
	Use:     "sa [serviceaccount]",
	Short:   "Show Kubernetes access for serviceaccount",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		opts, err := ValidateCommonFlags(cmd, args)
		if err != nil {
			return err
		}
		return RunAccessCheck(cmd, args, true, opts)
	},
}

func init() {
	addCommonFlags(SaCmd)
}
