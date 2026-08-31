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
	"aw beads-mail announces":   {},
	"aw beads-mail archive":     {},
	"aw beads-mail check":       {},
	"aw beads-mail claim":       {},
	"aw beads-mail clear":       {},
	"aw beads-mail delete":      {},
	"aw beads-mail drain":       {},
	"aw beads-mail help":        {},
	"aw beads-mail inbox":       {},
	"aw beads-mail mark-read":   {},
	"aw beads-mail mark-unread": {},
	"aw beads-mail peek":        {},
	"aw beads-mail read":        {},
	"aw beads-mail release":     {},
	"aw beads-mail reply":       {},
	"aw beads-mail search":      {},
	"aw beads-mail send":        {},
	"aw beads-mail thread":      {},
	"aw chat extend-wait":       {},
	"aw chat history":           {},
	"aw chat open":              {},
	"aw chat pending":           {},
	"aw chat read":              {},
	"aw chat send":              {},
	"aw chat send-and-leave":    {},
	"aw chat send-and-wait":     {},
	"aw check":                  {},
	"aw claim-human":            {},
	"aw doctor":                 {},
	"aw doctor identity":        {},
	"aw doctor registry":        {},
	"aw doctor support-bundle":  {},
	"aw id create":              {},
	"aw id team accept-invite":  {},
	"aw id team leave":          {},
	"aw id team list":           {},
	"aw id team request":        {},
	"aw id team switch":         {},
	"aw mail ack":               {},
	"aw mail inbox":             {},
	"aw mail reply":             {},
	"aw mail send":              {},
	"aw mail show":              {},
	"aw reset":                  {},
	"aw role-name set":          {},
	"aw run":                    {},
	"aw session lease acquire":  {},
	"aw session lease release":  {},
	"aw session lease renew":    {},
	"aw session lease status":   {},
	"aw session lease takeover": {},
	"aw task close":             {},
	"aw task comment add":       {},
	"aw task comment list":      {},
	"aw task create":            {},
	"aw task delete":            {},
	"aw task dep add":           {},
	"aw task dep list":          {},
	"aw task dep remove":        {},
	"aw task list":              {},
	"aw task reopen":            {},
	"aw task show":              {},
	"aw task stats":             {},
	"aw task update":            {},
	"aw whoami":                 {},
	"aw work active":            {},
	"aw work blocked":           {},
	"aw work ready":             {},
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
