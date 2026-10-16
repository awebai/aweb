package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Installing the Codex activity hook on a host that OATS does not manage. The
// command line is constant, so the hook's trust hash in Codex changes only when
// these entries do. OATS installs the same hook as a managed hook instead.

const codexActivityHookCommand = "aw activity hook"

type codexHookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Async   bool   `json:"async,omitempty"`
	Timeout int    `json:"timeout"`
}

// Tool and prompt events run in the background so they never delay Codex.
// The turn's end runs in the foreground: an unfinished background hook is
// cancelled when the session ends. Interrupt and SessionEnd allow at most 3 s.
var codexActivityHookEvents = []struct {
	event   string
	handler codexHookHandler
}{
	{"UserPromptSubmit", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"PreToolUse", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"PostToolUse", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"PermissionRequest", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"Stop", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Timeout: 10}},
	{"Interrupt", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Timeout: 3}},
	{"SessionEnd", codexHookHandler{Type: "command", Command: codexActivityHookCommand, Timeout: 3}},
}

func init() {
	install := &cobra.Command{Use: "install", Short: "Install the activity hook into a runtime's hook configuration", Args: cobra.NoArgs, RunE: runActivityHookInstall}
	install.Flags().Bool("codex", false, "Install into Codex's user hooks ($CODEX_HOME/hooks.json)")
	activityHookCmd.AddCommand(install)
}

func runActivityHookInstall(cmd *cobra.Command, _ []string) error {
	if codex, _ := cmd.Flags().GetBool("codex"); !codex {
		return usageError("name the runtime to install into: --codex")
	}
	dir := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(home, ".codex")
	}
	path := filepath.Join(dir, "hooks.json")
	changed, err := installCodexActivityHooks(dir)
	if err != nil {
		return fmt.Errorf("refusing to change %s: %w", path, err)
	}
	state := "is already installed"
	if changed {
		state = "is installed"
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "The aw activity hook %s in %s.\nCodex skips a new or changed hook until you trust it: review it with /hooks in Codex.\nPublishing stays off until you run: aw activity enable\n", state, path)
	return err
}

// installCodexActivityHooks adds the activity handler to every event that does
// not have it, keeping everything else in the file. It reports whether it wrote.
func installCodexActivityHooks(dir string) (bool, error) {
	path := filepath.Join(dir, "hooks.json")
	top := map[string]json.RawMessage{}
	mode := os.FileMode(0o600)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if json.Unmarshal(data, &top) != nil || top == nil {
			return false, errors.New("it is not a JSON object")
		}
		if info, statErr := os.Stat(path); statErr == nil {
			mode = info.Mode().Perm()
		}
	case !os.IsNotExist(err):
		return false, err
	}
	events := map[string][]json.RawMessage{}
	if raw, ok := top["hooks"]; ok {
		var byEvent map[string]json.RawMessage
		if json.Unmarshal(raw, &byEvent) != nil || byEvent == nil {
			return false, errors.New(`"hooks" is not an object`)
		}
		for event, rawGroups := range byEvent {
			var groups []json.RawMessage
			if json.Unmarshal(rawGroups, &groups) != nil || groups == nil {
				return false, fmt.Errorf(`"hooks.%s" is not an array`, event)
			}
			for _, group := range groups {
				if _, err := codexGroupHandlers(group); err != nil {
					return false, fmt.Errorf(`"hooks.%s": %w`, event, err)
				}
			}
			events[event] = groups
		}
	}
	changed := false
	for _, entry := range codexActivityHookEvents {
		if codexEventHasActivityHook(events[entry.event]) {
			continue
		}
		group, err := json.Marshal(struct {
			Hooks []codexHookHandler `json:"hooks"`
		}{Hooks: []codexHookHandler{entry.handler}})
		if err != nil {
			return false, err
		}
		events[entry.event] = append(events[entry.event], group)
		changed = true
	}
	if !changed {
		return false, nil
	}
	if top["hooks"], err = json.Marshal(events); err != nil {
		return false, err
	}
	var out bytes.Buffer
	encoded, err := json.Marshal(top)
	if err != nil {
		return false, err
	}
	if err = json.Indent(&out, encoded, "", "  "); err != nil {
		return false, err
	}
	out.WriteByte('\n')
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	return true, writeFileAtomic(dir, "hooks.json", out.Bytes(), mode)
}

// codexGroupHandlers reads a matcher group's handlers, refusing a shape it
// does not know rather than rewriting it.
func codexGroupHandlers(group json.RawMessage) ([]map[string]any, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(group, &fields) != nil || fields == nil {
		return nil, errors.New("a matcher group is not an object")
	}
	var handlers []map[string]any
	if raw, ok := fields["hooks"]; ok {
		if json.Unmarshal(raw, &handlers) != nil {
			return nil, errors.New(`a matcher group's "hooks" is not an array of objects`)
		}
	}
	return handlers, nil
}

func codexEventHasActivityHook(groups []json.RawMessage) bool {
	for _, group := range groups {
		handlers, _ := codexGroupHandlers(group)
		for _, handler := range handlers {
			if handler["type"] == "command" && handler["command"] == codexActivityHookCommand {
				return true
			}
		}
	}
	return false
}
