package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func markDeprecatedHiddenFlag(cmd *cobra.Command, name, replacement string) {
	if cmd == nil || cmd.Flags() == nil {
		return
	}
	message := fmt.Sprintf("use --%s", replacement)
	_ = cmd.Flags().MarkDeprecated(name, message)
	_ = cmd.Flags().MarkHidden(name)
}
