package main

import (
	"strings"

	"github.com/spf13/cobra"
)

// identityHomeAwareCommandPaths is intentionally a positive, exact allowlist.
// A newly added command is denied under an external identity home until its
// current-principal paths have been reviewed and its production wiring tested.
var identityHomeAwareCommandPaths = map[string]struct{}{
	"aw a2a cancel": {}, "aw a2a card": {}, "aw a2a publish": {}, "aw a2a send": {}, "aw a2a status": {},
	"aw agent": {}, "aw agent profile show": {},
	"aw blueprint inspect": {}, "aw blueprint materialize": {}, "aw blueprint publish-profile": {},
	"aw chat extend-wait": {}, "aw chat history": {}, "aw chat listen": {}, "aw chat open": {}, "aw chat pending": {}, "aw chat read": {}, "aw chat send": {}, "aw chat send-and-leave": {}, "aw chat send-and-wait": {}, "aw chat show-pending": {},
	"aw contacts add": {}, "aw contacts list": {}, "aw contacts remove": {},
	"aw control interrupt": {}, "aw control pause": {}, "aw control resume": {},
	"aw directory": {}, "aw events stream": {}, "aw heartbeat": {},
	"aw id addresses": {}, "aw id encryption-key rotate": {}, "aw id encryption-key setup": {}, "aw id encryption-key show": {}, "aw id log": {}, "aw id namespace addresses": {}, "aw id namespace resolve": {}, "aw id resolve": {}, "aw id rotate-key": {}, "aw id show": {}, "aw id verify": {},
	"aw inbound-mode":          {},
	"aw instructions activate": {}, "aw instructions history": {}, "aw instructions reset": {}, "aw instructions set": {}, "aw instructions show": {},
	"aw lock acquire": {}, "aw lock list": {}, "aw lock release": {}, "aw lock renew": {}, "aw lock revoke": {},
	"aw log":      {},
	"aw mail ack": {}, "aw mail inbox": {}, "aw mail reply": {}, "aw mail send": {}, "aw mail show": {},
	"aw mcp-config": {}, "aw notify": {},
	"aw plugin install": {}, "aw plugin list": {}, "aw plugin remove": {}, "aw plugin reserved-names": {}, "aw plugin update": {},
	"aw reset": {}, "aw role-name set": {},
	"aw roles activate": {}, "aw roles add": {}, "aw roles deactivate": {}, "aw roles history": {}, "aw roles list": {}, "aw roles reset": {}, "aw roles set": {}, "aw roles show": {},
	"aw run":        {},
	"aw task close": {}, "aw task comment add": {}, "aw task comment list": {}, "aw task create": {}, "aw task delete": {}, "aw task dep add": {}, "aw task dep list": {}, "aw task dep remove": {}, "aw task list": {}, "aw task reopen": {}, "aw task show": {}, "aw task stats": {}, "aw task update": {},
	"aw upgrade": {}, "aw version": {}, "aw whoami": {},
	"aw work active": {}, "aw work blocked": {}, "aw work ready": {},
	"aw workspace delete": {}, "aw workspace status": {},
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
