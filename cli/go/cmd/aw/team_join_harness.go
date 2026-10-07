package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

// Setup is separate from admission: a failed installer must never cause another
// redemption of a single-use invite or imply rollback of installed membership.
type joinHarnessResult struct {
	Harness      string            `json:"harness"`
	Status       string            `json:"status"`
	Docs         *injectDocsResult `json:"docs,omitempty"`
	Delivery     string            `json:"delivery,omitempty"`
	StartCommand string            `json:"start_command,omitempty"`
	RetryCommand string            `json:"retry_command,omitempty"`
}

func validateTeamJoinArgs(cmd *cobra.Command, args []string) error {
	switch teamHumanJoinHarness {
	case "", "claude", "codex", "pi":
	default:
		return usageError("--harness must be claude, codex, or pi")
	}
	if cmd.Flags().Changed("harness") && teamHumanJoinHarness == "" {
		return usageError("--harness must be claude, codex, or pi")
	}
	if teamHumanJoinHarness != "" && teamHumanJoinNoConnect {
		return usageError("--harness cannot be combined with --no-connect; harness setup requires a connected workspace")
	}
	if teamHumanJoinSetupOnly {
		if teamHumanJoinHarness == "" {
			return usageError("--setup-only requires --harness claude|codex|pi")
		}
		if len(args) != 0 {
			return usageError("--setup-only takes no invite token; it only configures the connected workspace")
		}
		for _, name := range []string{"name", "alias", "local", "global", "no-address", "address", "no-connect"} {
			if cmd.Flags().Changed(name) {
				return usageError("--setup-only cannot be combined with --%s", name)
			}
		}
		return nil
	}
	return cobra.ExactArgs(1)(cmd, args)
}

func joinHarnessRetryCommand(home awconfig.IdentityHome, harness string) string {
	args := []string{"aw"}
	if home.External() {
		args = append(args, "--identity-home", home.Root)
	}
	return formatShellCommand(append(args, "team", "join", "--setup-only", "--harness", harness))
}

func setupJoinHarness(workingDir string, home awconfig.IdentityHome, harness string) (*joinHarnessResult, error) {
	result := &joinHarnessResult{Harness: harness, Status: "incomplete", RetryCommand: joinHarnessRetryCommand(home, harness)}
	// Require the selected home's actual binding before writing docs or invoking
	// installers. Do not inherit a parent workspace or bootstrap an identity.
	path, err := awconfig.IdentityHomePath(home, "workspace.yaml")
	if err != nil {
		return result, err
	}
	if _, err := awconfig.LoadWorktreeWorkspaceFrom(path); err != nil {
		if recovery, ok := workspaceConnectRecoveryCommand(workingDir, externalIdentityHomeRoot(home)); ok {
			return result, fmt.Errorf("harness setup requires a connected workspace: %w; run `%s` first", err, recovery)
		}
		return result, fmt.Errorf("harness setup requires an existing connected workspace in the selected identity home: %w; run this command in the directory where join completed", err)
	}
	if _, _, err := resolveClientSelectionAtIdentityHome(workingDir, home); err != nil {
		return result, err
	}
	// Join targets this directory, even if it happens to sit inside a larger repo.
	result.Docs = InjectAgentDocsAtIdentityHome(workingDir, home)
	if len(result.Docs.Errors) > 0 {
		return result, fmt.Errorf("team docs: %s", strings.Join(result.Docs.Errors, "; "))
	}
	switch harness {
	case "claude":
		installed := ensureClaudeChannelPlugin(channelPluginOptions{RequireClaude: true}, func(args ...string) error {
			command := exec.Command("claude", args...)
			// Keep installer chatter separate from the structured join result.
			command.Stdout, command.Stderr = os.Stderr, os.Stderr
			return command.Run()
		})
		if installed.Error != nil {
			return result, installed.Error
		}
		result.Delivery = "native channel plugin installed; session not launched or verified"
		result.StartCommand = "claude --dangerously-skip-permissions --dangerously-load-development-channels " + claudeChannelSpec
	case "pi":
		if installed := EnsurePiChannelExtension(); installed.Error != nil {
			return result, installed.Error
		}
		result.Delivery = "native channel extension installed; session not launched or verified"
		result.StartCommand = "pi --approve"
	case "codex":
		result.Delivery = "aw run event-stream delivery; start the session to enable it (not launched or verified)"
		result.StartCommand = "aw run codex"
	}
	result.Status = "prepared"
	result.RetryCommand = ""
	return result, nil
}

func runJoinHarnessSetupOnly(cmd *cobra.Command) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	result, err := setupJoinHarness(workingDir, home, teamHumanJoinHarness)
	printOutput(*result, func(v any) string { return formatJoinHarnessSetup(v.(joinHarnessResult)) })
	if err != nil {
		return fmt.Errorf("harness setup failed: %w\nRun `%s` here after correcting the error; no invite is needed", err, result.RetryCommand)
	}
	return nil
}

func formatJoinHarnessSetup(result joinHarnessResult) string {
	text := fmt.Sprintf("Harness: %s (%s)\n", result.Harness, result.Status)
	if result.Delivery != "" {
		text += result.Delivery + "\n"
	}
	if result.StartCommand != "" {
		text += "Start: " + result.StartCommand + "\n"
	}
	if result.RetryCommand != "" {
		text += "Retry setup: " + result.RetryCommand + "\n"
	}
	return text
}
