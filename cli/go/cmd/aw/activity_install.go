package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

// Installing the Codex activity hook on a host that OATS does not manage. The
// command line is constant, so the hook's trust hash in Codex changes only when
// these entries do. OATS installs the same hook as a managed hook instead.

const codexActivityHookCommand = "aw activity hook"

type codexHookHandler struct {
	Type    runtimeHookKind `json:"type"`
	Command string          `json:"command"`
	Async   bool            `json:"async,omitempty"`
	Timeout int             `json:"timeout"`
}

// Tool and prompt events run in the background so they never delay Codex.
// The turn's end runs in the foreground: an unfinished background hook is
// cancelled when the session ends. Interrupt and SessionEnd allow at most 3 s.
var codexActivityHookEvents = []struct {
	event   string
	handler codexHookHandler
}{
	{"UserPromptSubmit", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"PreToolUse", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"PostToolUse", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"PermissionRequest", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Async: true, Timeout: 10}},
	{"Stop", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Timeout: 10}},
	{"Interrupt", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Timeout: 3}},
	{"SessionEnd", codexHookHandler{Type: commandHookKind, Command: codexActivityHookCommand, Timeout: 3}},
}

func init() {
	install := &cobra.Command{Use: "install", Short: "Install the activity hook into a runtime's hook configuration", Args: cobra.NoArgs, RunE: runActivityHookInstall}
	install.Flags().Bool("codex", false, "Install into Codex's user hooks ($CODEX_HOME/hooks.json)")
	uninstall := &cobra.Command{Use: "uninstall", Short: "Remove the aw activity hook from a runtime", Args: cobra.NoArgs, RunE: runActivityHookUninstall}
	uninstall.Flags().Bool("codex", false, "Remove from Codex user hooks ($CODEX_HOME/hooks.json)")
	activityHookCmd.AddCommand(install, uninstall)
}

func runActivityHookInstall(cmd *cobra.Command, _ []string) error {
	codex, err := cmd.Flags().GetBool("codex")
	if err != nil {
		return err
	}
	if !codex {
		return usageError("name the runtime to install into: --codex")
	}
	dir, err := codexHookDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "hooks.json")
	changed, err := installCodexActivityHooks(dir)
	if err != nil {
		return fmt.Errorf("refusing to change %s: %w. Repair hooks.json and retry aw activity hook install --codex.", path, err)
	}
	state := "is already installed"
	if changed {
		state = "is installed"
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "The aw activity hook %s in %s.\nCodex skips a new or changed hook until you trust it: review it with /hooks in Codex.\nPublishing stays off until you run: aw activity enable\n", state, path)
	return err
}

func runActivityHookUninstall(cmd *cobra.Command, _ []string) error {
	codex, err := cmd.Flags().GetBool("codex")
	if err != nil {
		return err
	}
	if !codex {
		return usageError("name the runtime to remove from: --codex")
	}
	dir, err := codexHookDirectory()
	if err != nil {
		return err
	}
	changed, err := changeCodexActivityHooks(dir, removeActivityHook)
	if err != nil {
		return fmt.Errorf("refusing to change %s: %w. Repair hooks.json and retry aw activity hook uninstall --codex.", filepath.Join(dir, "hooks.json"), err)
	}
	state := "was already absent"
	if changed {
		state = "was removed"
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "The aw activity hook %s in %s.\n", state, filepath.Join(dir, "hooks.json"))
	return err
}

func installCodexActivityHooks(dir string) (bool, error) {
	return changeCodexActivityHooks(dir, installActivityHook)
}

type activityHookOperation uint8

const (
	installActivityHook activityHookOperation = iota
	removeActivityHook
)

func changeCodexActivityHooks(dir string, operation activityHookOperation) (bool, error) {
	path := filepath.Join(dir, "hooks.json")
	plan, err := planCodexActivityFileEdit(path, operation)
	if err != nil || !plan.Changed {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	changed := false
	err = withHookSettingsLock(path, func() error {
		current, err := planCodexActivityFileEdit(path, operation)
		if err != nil || !current.Changed {
			return err
		}
		if err := atomicfile.Write(path, current.Data, current.Mode); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}

type codexActivityFileEdit struct {
	Data    []byte
	Mode    os.FileMode
	Changed bool
}

func planCodexActivityFileEdit(path string, operation activityHookOperation) (codexActivityFileEdit, error) {
	if err := pathpreflight.PreflightFile(path, "Codex hook config", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return codexActivityFileEdit{}, err
	}
	data, err := os.ReadFile(path)
	mode := os.FileMode(0o600)
	if os.IsNotExist(err) {
		if operation == removeActivityHook {
			return codexActivityFileEdit{}, nil
		}
		data = []byte("{}\n")
	} else if err != nil {
		return codexActivityFileEdit{}, err
	} else {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return codexActivityFileEdit{}, statErr
		}
		mode = info.Mode().Perm()
	}
	updated, changed, err := editCodexActivityHooks(data, operation)
	if err != nil {
		return codexActivityFileEdit{}, hookSettingsParseError(path, err)
	}
	return codexActivityFileEdit{Data: updated, Mode: mode, Changed: changed}, nil
}

// editCodexActivityHooks implements docs/runtime-hook-configuration.md:3-7 for the
// unscoped activity handlers installed by aw.
func editCodexActivityHooks(data []byte, operation activityHookOperation) ([]byte, bool, error) {
	root, err := parseHookJSON(data)
	if err != nil {
		return nil, false, err
	}
	hooks := root.member("hooks")
	if hooks != nil && hooks.object == nil {
		return nil, false, &hookJSONError{Problem: nonObjectHooks, Detail: "hooks must be an object"}
	}
	if err := validateCodexHookEvents(hooks); err != nil {
		return nil, false, err
	}
	var edits []hookJSONEdit
	var newEvents []string
	for _, entry := range codexActivityHookEvents {
		groups := hooks.member(entry.event)
		found := false
		if groups != nil {
			removeGroups := make([]bool, len(groups.array))
			for i, group := range groups.array {
				groupEdit, err := planCodexActivityGroup(data, group, operation)
				if err != nil {
					return nil, false, err
				}
				found = found || groupEdit.Found
				removeGroups[i] = groupEdit.RemoveGroup
				edits = append(edits, groupEdit.Edits...)
			}
			if operation == removeActivityHook {
				spans, err := hookArrayRemovalSpans(data, groups.array, removeGroups)
				if err != nil {
					return nil, false, err
				}
				for _, span := range spans {
					edits = append(edits, hookJSONEdit{start: span.start, end: span.end})
				}
			}
		}
		if operation == removeActivityHook || found {
			continue
		}
		handler, err := json.Marshal(entry.handler)
		if err != nil {
			return nil, false, err
		}
		group := `{"hooks":[` + string(handler) + `]}`
		if groups != nil {
			edits = append(edits, appendHookJSON(groups, group))
		} else {
			key, err := json.Marshal(entry.event)
			if err != nil {
				return nil, false, err
			}
			newEvents = append(newEvents, string(key)+`:[`+group+`]`)
		}
	}
	if len(newEvents) > 0 {
		if hooks == nil {
			edits = append(edits, appendHookJSON(root, `"hooks":{`+strings.Join(newEvents, ",")+`}`))
		} else {
			edits = append(edits, appendHookJSON(hooks, strings.Join(newEvents, ",")))
		}
	}
	if len(edits) == 0 {
		return data, false, nil
	}
	updated, err := editHookJSON(data, edits)
	if err != nil {
		return nil, false, err
	}
	return updated, true, nil
}

func validateCodexHookEvents(hooks *hookJSONNode) error {
	if hooks == nil {
		return nil
	}
	for event, groups := range hooks.object {
		if groups.value != json.Delim('[') {
			return fmt.Errorf("hooks.%s must be an array", event)
		}
		for _, group := range groups.array {
			if group.object == nil {
				return fmt.Errorf("hooks.%s groups must be objects", event)
			}
			inner := group.member("hooks")
			if inner == nil {
				continue
			}
			if inner.value != json.Delim('[') {
				return fmt.Errorf("hooks.%s handlers must be an array", event)
			}
			for _, handler := range inner.array {
				if handler.object == nil {
					return fmt.Errorf("hooks.%s handlers must be objects", event)
				}
			}
		}
	}
	return nil
}

type codexActivityGroupEdit struct {
	Found       bool
	RemoveGroup bool
	Edits       []hookJSONEdit
}

func planCodexActivityGroup(data []byte, group *hookJSONNode, operation activityHookOperation) (codexActivityGroupEdit, error) {
	result := codexActivityGroupEdit{}
	// aw installs unscoped groups; a custom matcher belongs to its user.
	if group.member("matcher") != nil {
		return result, nil
	}
	inner := group.member("hooks")
	if inner == nil {
		return result, nil
	}
	remove := make([]bool, len(inner.array))
	count := 0
	for i, handler := range inner.array {
		if handler.member("type").stringValue() == string(commandHookKind) && handler.member("command").stringValue() == codexActivityHookCommand {
			remove[i] = true
			count++
		}
	}
	result.Found = count > 0
	if operation == installActivityHook || !result.Found {
		return result, nil
	}
	if count == len(inner.array) && len(group.object) == 1 {
		result.RemoveGroup = true
		return result, nil
	}
	spans, err := hookArrayRemovalSpans(data, inner.array, remove)
	if err != nil {
		return result, err
	}
	for _, span := range spans {
		result.Edits = append(result.Edits, hookJSONEdit{start: span.start, end: span.end})
	}
	return result, nil
}

func codexHookDirectory() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("CODEX_HOME")); configured != "" {
		return configured, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex"), nil
}
