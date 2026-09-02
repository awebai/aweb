package main

// Address mapping for the beads mail delegate, per docs/beads-mail-delegate.md
// §5: a per-repo .beads/aweb-mail.toml maps beads-style local names to aweb
// addresses; anything already carrying a domain or a DID passes through. The
// map is repo-controlled data that redirects mail sent under the user's
// verified identity, so resolution always reports the resolved address for
// disclosure.
//
// The parser, the value grammar and the resolution order live in
// mail_delegate_address.go, shared with `aw gc-mail`. This file is the beads
// binding of that machinery: where the file lives, and the names the beads
// code and its tests already use.

const beadsMailMapFileName = "aweb-mail.toml"

// beadsMailMapSpec: bd finds its repo state at .beads, pinned by BEADS_DIR
// when set — and BEADS_DIR names that directory itself, not its parent.
var beadsMailMapSpec = delegateMailMapSpec{
	envVar:            "BEADS_DIR",
	envNamesMarkerDir: true,
	markerDir:         ".beads",
	fileName:          beadsMailMapFileName,
}

type (
	beadsMailTarget     = delegateMailTarget
	beadsMailAddressMap = delegateMailAddressMap
)

func loadBeadsMailAddressMap(startDir string) (beadsMailAddressMap, error) {
	return loadDelegateMailAddressMap(startDir, beadsMailMapSpec)
}

func resolveBeadsMailRecipient(m beadsMailAddressMap, input string) (beadsMailTarget, error) {
	return resolveDelegateMailRecipient(m, input)
}

func beadsMailDisplayName(m beadsMailAddressMap, value string) string {
	return delegateMailDisplayName(m, value)
}

func beadsMailResolutionNote(t beadsMailTarget) string {
	return delegateMailResolutionNote(t)
}

func sanitizeBeadsMailDisplay(s string) string {
	return sanitizeDelegateMailDisplay(s)
}

func sanitizeBeadsMailBody(s string) string {
	return sanitizeDelegateMailBody(s)
}
