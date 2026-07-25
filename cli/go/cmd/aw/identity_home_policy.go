package main

import (
	"strings"

	"github.com/spf13/cobra"
)

// identityHomeNeutralCommandExemptions is the complete pointer-identity set of
// commands that never access principal state and therefore bypass admission.
// Its exact population and real-binary behavior are guarded in tests.
var identityHomeNeutralCommandExemptions = map[*cobra.Command]struct{}{
	versionCmd: {},
	upgradeCmd: {},
}

func isIdentityHomeNeutralCommand(cmd *cobra.Command) bool {
	_, ok := identityHomeNeutralCommandExemptions[cmd]
	return ok
}

// identityHomeAwareCommandPaths is intentionally a positive, exact allowlist.
// Every entry has a production-binary regression against an external principal
// and an empty instance. A newly added command is denied until equivalent
// evidence is added; plausible-looking code is not sufficient evidence.
var identityHomeAwareCommandPaths = map[string]struct{}{
	"aw a2a status":       {},
	"aw id create":        {},
	"aw mail inbox":       {},
	"aw reset":            {},
	"aw role-name set":    {},
	"aw run":              {},
	"aw whoami":           {},
	"aw workspace delete": {},
}

func requireIdentityHomeAwareCommand(cmd *cobra.Command, external bool) error {
	if !external || cmd == nil {
		return nil
	}
	path := strings.TrimSpace(cmd.CommandPath())
	if _, ok := identityHomeAwareCommandPaths[path]; ok {
		return nil
	}
	return usageError("command %q is not yet identity-home-aware; refusing to use an external identity home so principal state cannot fall back to the instance directory", path)
}
