package main

import (
	"context"

	"github.com/awebai/aw/awid"
)

// commandAPIContext applies the normal API budget to one command operation.
// Commands pass cmd.Context(); helpers with a caller context preserve it.
// Standalone operations without a caller context use a background parent.
// Long polls, interactive waits and short health probes keep explicit budgets.
func commandAPIContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		// Cobra commands invoked directly by an embedding caller may have no
		// context yet; ordinary execution supplies the inherited command context.
		parent = context.Background()
	}
	return context.WithTimeout(parent, awid.APITimeout())
}
