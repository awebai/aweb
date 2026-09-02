package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
)

// Shared address mapping for the aweb mail delegates: `aw beads-mail` (the bd
// mail delegate, docs/beads-mail-delegate.md §5) and `aw gc-mail` (the Gas
// City exec mail provider, docs/gascity-mail-provider.md §4). Both host
// runtimes hand us a runtime-local recipient name; both resolve it through the
// same order, the same strict-TOML per-repo map, and the same value grammar.
// The only per-runtime differences are where the map file lives and what the
// unmapped-name error tells the user to edit, so those ride a spec rather than
// a second copy of this code.

// delegateMailMapSpec locates one runtime's per-repo address map.
//
//	envVar            names the environment variable that pins the location.
//	envNamesMarkerDir is true when that variable holds the marker directory
//	                  itself (BEADS_DIR is the .beads directory), false when it
//	                  holds the directory CONTAINING the marker (GC_CITY is the
//	                  city root, whose marker is .gc).
//	markerDir         is the directory searched for by walking up from the
//	                  working directory when the variable is unset.
//	fileName          is the map file inside the marker directory.
type delegateMailMapSpec struct {
	envVar            string
	envNamesMarkerDir bool
	markerDir         string
	fileName          string
}

// displayPath is the path quoted in the unmapped-name error when no map file
// was found on disk, so the error still names a file the user can create.
func (s delegateMailMapSpec) displayPath() string {
	if s.markerDir == "" || s.fileName == "" {
		// A zero spec can only reach here through a map value that was never
		// loaded; name something actionable rather than an empty path.
		return "the delegate's aweb-mail.toml"
	}
	return filepath.Join(s.markerDir, s.fileName)
}

// delegateMailTarget is one resolved recipient.
type delegateMailTarget struct {
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

// delegateMailAddressMap is the parsed [addresses] table plus the optional
// [settings] table and where they came from, so error and disclosure text can
// name the file.
type delegateMailAddressMap struct {
	entries  map[string]string
	settings map[string]string
	path     string
	spec     delegateMailMapSpec
}

// loadDelegateMailAddressMap locates and parses the per-repo map. The marker
// directory is found the way the host runtime finds it: the spec's environment
// variable when set, otherwise walking up from startDir. A missing directory or
// missing map file is not an error — only an unmapped runtime-local name is, at
// resolution time.
func loadDelegateMailAddressMap(startDir string, spec delegateMailMapSpec) (delegateMailAddressMap, error) {
	none := delegateMailAddressMap{entries: map[string]string{}, settings: map[string]string{}, spec: spec}
	markerDir := ""
	if spec.envVar != "" {
		if value := strings.TrimSpace(os.Getenv(spec.envVar)); value != "" {
			if spec.envNamesMarkerDir {
				markerDir = value
			} else {
				markerDir = filepath.Join(value, spec.markerDir)
			}
		}
	}
	if markerDir == "" {
		dir, err := filepath.Abs(startDir)
		if err != nil {
			return none, err
		}
		for {
			candidate := filepath.Join(dir, spec.markerDir)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				markerDir = candidate
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return none, nil
			}
			dir = parent
		}
	}
	path := filepath.Join(markerDir, spec.fileName)
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	entries, settings, err := parseDelegateMailAddressMap(string(content), path)
	if err != nil {
		return none, err
	}
	return delegateMailAddressMap{entries: entries, settings: settings, path: path, spec: spec}, nil
}

// parseDelegateMailAddressMap reads the strict subset of TOML the design
// records fix for this file: comments, blank lines, one [addresses] table of
// quoted (or bare single-word) keys assigned quoted string values, and one
// optional [settings] table of known keys. Anything else is rejected loudly
// with the file named — misparsing a mail-routing map is worse than refusing
// it.
func parseDelegateMailAddressMap(content, path string) (map[string]string, map[string]string, error) {
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
		key, value, err := parseDelegateMailMapLine(line)
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
		if err := validateDelegateMailAddressValue(value); err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %q = %q: %v", path, lineNo+1, key, value, err)
		}
		if _, dup := entries[key]; dup {
			return nil, nil, fmt.Errorf("%s:%d: duplicate entry for %q", path, lineNo+1, key)
		}
		entries[key] = value
	}
	return entries, settings, nil
}

func parseDelegateMailMapLine(line string) (string, string, error) {
	if strings.ContainsAny(line, "\\") {
		return "", "", fmt.Errorf("backslashes are not supported in this file")
	}
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", fmt.Errorf("expected \"name\" = \"aweb-address\"")
	}
	key, err := unquoteDelegateMailToken(strings.TrimSpace(line[:eq]), true)
	if err != nil {
		return "", "", err
	}
	value, err := unquoteDelegateMailToken(strings.TrimSpace(line[eq+1:]), false)
	if err != nil {
		return "", "", err
	}
	if key == "" || value == "" {
		return "", "", fmt.Errorf("expected \"name\" = \"aweb-address\"")
	}
	return key, value, nil
}

func unquoteDelegateMailToken(token string, allowBare bool) (string, error) {
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

// validateDelegateMailAddressValue enforces the two accepted value forms at map
// load, so an email-style value fails with a helpful message instead of as a
// late "not found" (beads-mail record §5). The same shape check gates address
// passthrough at resolution time, so a malformed input never rides through to
// the server as a raw "address".
func validateDelegateMailAddressValue(value string) error {
	if strings.HasPrefix(value, "did:aw:") {
		return nil
	}
	if isWellFormedDelegateMailAddress(value) {
		return nil
	}
	return fmt.Errorf("not an aweb address; use domain/name (like acme.aweb.ai/reviewer) or did:aw:...")
}

func isWellFormedDelegateMailAddress(value string) bool {
	if strings.ContainsAny(value, "@ \t") || containsDelegateMailControlRune(value) {
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

// resolveDelegateMailRecipient applies the beads-mail record's §5 resolution
// order, which docs/gascity-mail-provider.md §4 adopts unchanged.
func resolveDelegateMailRecipient(m delegateMailAddressMap, input string) (delegateMailTarget, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return delegateMailTarget{}, usageError("recipient is required")
	}
	if value, ok := m.entries[trimmed]; ok {
		kind := "address"
		if strings.HasPrefix(value, "did:") {
			kind = "did"
		}
		return delegateMailTarget{Kind: kind, Value: value, Input: trimmed, Mapped: true}, nil
	}
	if strings.HasPrefix(trimmed, "did:") {
		return delegateMailTarget{Kind: "did", Value: trimmed, Input: trimmed}, nil
	}
	if strings.HasPrefix(trimmed, "list:") {
		return delegateMailTarget{}, usageError("mailing lists (%s) are not supported in v1; send to each recipient", trimmed)
	}
	normalized := awid.NormalizeHostedHandleAddress(trimmed)
	if isWellFormedDelegateMailAddress(normalized) {
		return delegateMailTarget{Kind: "address", Value: normalized, Input: trimmed}, nil
	}
	if !strings.ContainsAny(trimmed, "/@") && !containsDelegateMailControlRune(trimmed) {
		return delegateMailTarget{Kind: "alias", Value: trimmed, Input: trimmed}, nil
	}
	return delegateMailTarget{}, unmappedDelegateMailNameError(m, trimmed)
}

// unmappedDelegateMailNameError is the step-6 error: the one error a user of
// either delegate is expected to meet before reading any documentation, so it
// carries the exact line to add and the file to add it to.
func unmappedDelegateMailNameError(m delegateMailAddressMap, name string) error {
	mapPath := m.path
	if mapPath == "" {
		mapPath = m.spec.displayPath()
	}
	return usageError("%q is not mapped to an aweb address.\nAdd it to %s:\n\n  [addresses]\n  %q = \"<domain/name or did:aw:...>\"", name, mapPath, name)
}

// delegateMailDisplayName returns the local map name for an aweb address or
// DID, for inbox/read display (reverse mapping). Deterministic under multiple
// keys mapping to one value: the lexically first key wins.
func delegateMailDisplayName(m delegateMailAddressMap, value string) string {
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

// delegateMailResolutionNote is the disclosure line a send prints where the
// host runtime leaves the delegate a channel to say it (beads-mail record §5).
// Control characters are neutralized here as well as at validation, so the
// disclosure line cannot be split or styled by a hostile recipient string even
// if a future resolution path forgets to validate.
func delegateMailResolutionNote(t delegateMailTarget) string {
	input := sanitizeDelegateMailDisplay(t.Input)
	value := sanitizeDelegateMailDisplay(t.Value)
	if value == input {
		return fmt.Sprintf("to %s", input)
	}
	return fmt.Sprintf("to %s -> %s", input, value)
}

func containsDelegateMailControlRune(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func sanitizeDelegateMailDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// sanitizeDelegateMailBody neutralizes terminal-driving control characters in
// an inbound body while keeping the text readable: newlines and tabs survive,
// everything else in C0 plus DEL (notably ESC, which drives ANSI/OSC escape
// sequences) becomes '?'. Senders are verified, not trusted.
func sanitizeDelegateMailBody(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
