package main

import (
	"context"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// commandAPIContext applies the normal API budget to one command operation.
// Commands pass cmd; helpers with a caller context can supply it explicitly.
// Standalone operations and direct nil-command invocations use a background parent.
// Long polls, interactive waits and short health probes keep explicit budgets.
func commandAPIContext(cmd *cobra.Command, parents ...context.Context) (context.Context, context.CancelFunc) {
	var parent context.Context
	if cmd != nil {
		parent = cmd.Context()
	}
	if len(parents) > 0 {
		parent = parents[0]
	}
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, awid.APITimeout())
}
