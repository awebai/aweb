package main

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// identityHomeNeutralCommandExemptions is the complete pointer-identity set of
// commands that never access principal state and therefore bypass admission.
// Its exact population and real-binary behavior are guarded in tests.
var identityHomeNeutralCommandExemptions = map[*cobra.Command]struct{}{
	pinStoreCompareAndSetCmd: {},
	versionCmd:               {},
	upgradeCmd:               {},
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
	"aw a2a status":             {},
	"aw claim-human":            {},
	"aw doctor identity":        {},
	"aw doctor registry":        {},
	"aw id create":              {},
	"aw id team accept-invite":  {},
	"aw id team leave":          {},
	"aw id team list":           {},
	"aw id team request":        {},
	"aw id team switch":         {},
	"aw mail inbox":             {},
	"aw reset":                  {},
	"aw role-name set":          {},
	"aw run":                    {},
	"aw whoami":                 {},
	"aw workspace add-worktree": {},
	"aw workspace delete":       {},
	"aw workspace status":       {},
}

func requireIdentityHomeAwareCommand(cmd *cobra.Command, external bool) error {
	if !external || cmd == nil {
		return nil
	}
	path := strings.TrimSpace(cmd.CommandPath())
	if _, ok := identityHomeAwareCommandPaths[path]; ok {
		return nil
	}
	alternatives := identityHomeAwareAlternatives(cmd, identityHomeAwareCommandPaths)
	if len(alternatives) == 0 {
		return usageError("command %q is not yet identity-home-aware; refusing to use an external identity home so principal state cannot fall back to the instance directory. No command in this group is currently supported for an attached principal; stop rather than running the command against the disposable instance", path)
	}
	return usageError("command %q is not yet identity-home-aware; refusing to use an external identity home so principal state cannot fall back to the instance directory. Supported alternatives for this attached principal: %s", path, strings.Join(alternatives, ", "))
}

func identityHomeAwareAlternatives(cmd *cobra.Command, allowed map[string]struct{}) []string {
	if cmd == nil {
		return nil
	}
	group := cmd
	for group.Parent() != nil && group.Parent().Parent() != nil {
		group = group.Parent()
	}
	prefix := strings.TrimSpace(group.CommandPath()) + " "
	alternatives := make([]string, 0, len(allowed))
	for path := range allowed {
		path = strings.TrimSpace(path)
		if strings.HasPrefix(path, prefix) {
			alternatives = append(alternatives, path)
		}
	}
	sort.Strings(alternatives)
	return alternatives
}
