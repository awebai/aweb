package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
)

// Address mapping for the beads mail delegate, per docs/beads-mail-delegate.md
// §5: a per-repo .beads/aweb-mail.toml maps beads-style local names to aweb
// addresses; anything already carrying a domain or a DID passes through. The
// map is repo-controlled data that redirects mail sent under the user's
// verified identity, so resolution always reports the resolved address for
// disclosure.

const beadsMailMapFileName = "aweb-mail.toml"

// beadsMailTarget is one resolved recipient.
type beadsMailTarget struct {
	// Kind is "did", "address", or "alias", matching the aw mail dispatch
	// convention.
	Kind string
	// Value is the resolved target: a did:aw DID, a domain/name address, or a
	// same-team alias.
	Value string
	// Input is the argument as the user wrote it, for disclosure output.
	Input string
	// Mapped is true when Value came from the per-repo map.
	Mapped bool
}

// beadsMailAddressMap is the parsed [addresses] table plus the optional
// [settings] table and where they came from, so error and disclosure text can
// name the file.
type beadsMailAddressMap struct {
	entries  map[string]string
	settings map[string]string
	path     string
}

// loadBeadsMailAddressMap locates and parses the per-repo map. The .beads
// directory is found the way bd finds it: BEADS_DIR when set, otherwise
// walking up from startDir. A missing directory or missing map file is not an
// error — only an unmapped rig-style name is, at resolution time.
func loadBeadsMailAddressMap(startDir string) (beadsMailAddressMap, error) {
	none := beadsMailAddressMap{entries: map[string]string{}, settings: map[string]string{}}
	beadsDir := strings.TrimSpace(os.Getenv("BEADS_DIR"))
	if beadsDir == "" {
		dir, err := filepath.Abs(startDir)
		if err != nil {
			return none, err
		}
		for {
			candidate := filepath.Join(dir, ".beads")
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				beadsDir = candidate
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return none, nil
			}
			dir = parent
		}
	}
	path := filepath.Join(beadsDir, beadsMailMapFileName)
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	entries, settings, err := parseBeadsMailAddressMap(string(content), path)
	if err != nil {
		return none, err
	}
	return beadsMailAddressMap{entries: entries, settings: settings, path: path}, nil
}

// parseBeadsMailAddressMap reads the strict subset of TOML the design record
// fixes for this file: comments, blank lines, one [addresses] table of quoted
// (or bare single-word) keys assigned quoted string values, and one optional
// [settings] table of known keys. Anything else is rejected loudly with the
// file named — misparsing a mail-routing map is worse than refusing it.
func parseBeadsMailAddressMap(content, path string) (map[string]string, map[string]string, error) {
	entries := map[string]string{}
	settings := map[string]string{}
	const (
		sectionNone = iota
		sectionAddresses
		sectionSettings
	)
	section := sectionNone
	seenAddresses, seenSettings := false, false
	for lineNo, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[addresses]":
				if seenAddresses {
					return nil, nil, fmt.Errorf("%s:%d: duplicate [addresses] table; this file holds one", path, lineNo+1)
				}
				seenAddresses = true
				section = sectionAddresses
			case "[settings]":
				if seenSettings {
					return nil, nil, fmt.Errorf("%s:%d: duplicate [settings] table; this file holds one", path, lineNo+1)
				}
				seenSettings = true
				section = sectionSettings
			default:
				return nil, nil, fmt.Errorf("%s:%d: unsupported table %s; this file supports the [addresses] table of \"name\" = \"aweb-address\" pairs and an optional [settings] table", path, lineNo+1, line)
			}
			continue
		}
		if section == sectionNone {
			return nil, nil, fmt.Errorf("%s:%d: entry before any table; start the file with [addresses]", path, lineNo+1)
		}
		key, value, err := parseBeadsMailMapLine(line)
		if err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %v", path, lineNo+1, err)
		}
		if section == sectionSettings {
			if key != "dual-write" {
				return nil, nil, fmt.Errorf("%s:%d: unknown setting %q; supported: dual-write", path, lineNo+1, key)
			}
			if value != "on" && value != "off" {
				return nil, nil, fmt.Errorf("%s:%d: %s must be \"on\" or \"off\", got %q", path, lineNo+1, key, value)
			}
			if _, dup := settings[key]; dup {
				return nil, nil, fmt.Errorf("%s:%d: duplicate setting %q", path, lineNo+1, key)
			}
			settings[key] = value
			continue
		}
		if err := validateBeadsMailAddressValue(value); err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %q = %q: %v", path, lineNo+1, key, value, err)
		}
		if _, dup := entries[key]; dup {
			return nil, nil, fmt.Errorf("%s:%d: duplicate entry for %q", path, lineNo+1, key)
		}
		entries[key] = value
	}
	return entries, settings, nil
}

func parseBeadsMailMapLine(line string) (string, string, error) {
	if strings.ContainsAny(line, "\\") {
		return "", "", fmt.Errorf("backslashes are not supported in this file")
	}
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", fmt.Errorf("expected \"name\" = \"aweb-address\"")
	}
	key, err := unquoteBeadsMailToken(strings.TrimSpace(line[:eq]), true)
	if err != nil {
		return "", "", err
	}
	value, err := unquoteBeadsMailToken(strings.TrimSpace(line[eq+1:]), false)
	if err != nil {
		return "", "", err
	}
	if key == "" || value == "" {
		return "", "", fmt.Errorf("expected \"name\" = \"aweb-address\"")
	}
	return key, value, nil
}

func unquoteBeadsMailToken(token string, allowBare bool) (string, error) {
	if strings.HasPrefix(token, "\"") {
		if len(token) < 2 || !strings.HasSuffix(token, "\"") {
			return "", fmt.Errorf("unterminated quoted string %s", token)
		}
		inner := token[1 : len(token)-1]
		if strings.Contains(inner, "\"") {
			return "", fmt.Errorf("embedded quotes are not supported in %s", token)
		}
		if strings.TrimSpace(inner) != inner {
			return "", fmt.Errorf("leading or trailing whitespace inside quotes in %s", token)
		}
		return inner, nil
	}
	if !allowBare {
		return "", fmt.Errorf("value must be a quoted string, got %s", token)
	}
	if token == "" || strings.ContainsAny(token, " \t\"'#[]") {
		return "", fmt.Errorf("key must be a quoted string or a bare single word, got %q", token)
	}
	return token, nil
}

// validateBeadsMailAddressValue enforces the two accepted value forms at map
// load, so an email-style value fails with a helpful message instead of as a
// late "not found" (design record §5). The same shape check gates address
// passthrough at resolution time, so a malformed input never rides through to
// the server as a raw "address".
func validateBeadsMailAddressValue(value string) error {
	if strings.HasPrefix(value, "did:aw:") {
		return nil
	}
	if isWellFormedBeadsMailAddress(value) {
		return nil
	}
	return fmt.Errorf("not an aweb address; use domain/name (like acme.aweb.ai/reviewer) or did:aw:...")
}

func isWellFormedBeadsMailAddress(value string) bool {
	if strings.ContainsAny(value, "@ \t") || containsBeadsMailControlRune(value) {
		return false
	}
	domain, name, ok := strings.Cut(value, "/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return false
	}
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	return true
}

// resolveBeadsMailRecipient applies the design record's §5 resolution order.
func resolveBeadsMailRecipient(m beadsMailAddressMap, input string) (beadsMailTarget, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return beadsMailTarget{}, usageError("recipient is required")
	}
	if value, ok := m.entries[trimmed]; ok {
		kind := "address"
		if strings.HasPrefix(value, "did:") {
			kind = "did"
		}
		return beadsMailTarget{Kind: kind, Value: value, Input: trimmed, Mapped: true}, nil
	}
	if strings.HasPrefix(trimmed, "did:") {
		return beadsMailTarget{Kind: "did", Value: trimmed, Input: trimmed}, nil
	}
	if strings.HasPrefix(trimmed, "list:") {
		return beadsMailTarget{}, usageError("mailing lists (%s) are not supported in v1; send to each recipient", trimmed)
	}
	normalized := awid.NormalizeHostedHandleAddress(trimmed)
	if isWellFormedBeadsMailAddress(normalized) {
		return beadsMailTarget{Kind: "address", Value: normalized, Input: trimmed}, nil
	}
	if !strings.ContainsAny(trimmed, "/@") && !containsBeadsMailControlRune(trimmed) {
		return beadsMailTarget{Kind: "alias", Value: trimmed, Input: trimmed}, nil
	}
	mapPath := m.path
	if mapPath == "" {
		mapPath = filepath.Join(".beads", beadsMailMapFileName)
	}
	return beadsMailTarget{}, usageError("%q is not mapped to an aweb address.\nAdd it to %s:\n\n  [addresses]\n  %q = \"<domain/name or did:aw:...>\"", trimmed, mapPath, trimmed)
}

// beadsMailDisplayName returns the local map name for an aweb address or DID,
// for inbox/read display (reverse mapping). Deterministic under multiple keys
// mapping to one value: the lexically first key wins.
func beadsMailDisplayName(m beadsMailAddressMap, value string) string {
	keys := make([]string, 0, len(m.entries))
	for key, mapped := range m.entries {
		if mapped == value {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return keys[0]
}

// beadsMailResolutionNote is the disclosure line every send prints (design
// record §5): the user must see where their attributed mail actually went.
// Control characters are neutralized here as well as at validation, so the
// disclosure line cannot be split or styled by a hostile recipient string
// even if a future resolution path forgets to validate.
func beadsMailResolutionNote(t beadsMailTarget) string {
	input := sanitizeBeadsMailDisplay(t.Input)
	value := sanitizeBeadsMailDisplay(t.Value)
	if value == input {
		return fmt.Sprintf("to %s", input)
	}
	return fmt.Sprintf("to %s -> %s", input, value)
}

func containsBeadsMailControlRune(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func sanitizeBeadsMailDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
