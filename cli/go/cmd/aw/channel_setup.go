package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	claudeChannelMarketplace = "awebai/claude-plugins"
	claudeChannelPlugin      = "aweb-channel@awebai-marketplace"
	claudeChannelSpec        = "plugin:" + claudeChannelPlugin

	piChannelExtensionPackage = "npm:@awebai/pi"
	piChannelExtensionSource  = piChannelExtensionPackage + "@latest"
)

var (
	runClaudeChannelPluginCommand = runClaudeChannelPluginCommandExec
	runPiChannelExtensionCommand  = runPiChannelExtensionCommandExec
)

func runClaudeChannelPluginCommandExec(args ...string) error {
	cmd := exec.Command("claude", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runPiChannelExtensionCommandExec(args ...string) ([]byte, error) {
	cmd := exec.Command("pi", args...)
	return cmd.CombinedOutput()
}

type channelPluginOptions struct {
	RequireClaude bool
}

func EnsureClaudeChannelPlugin(opts channelPluginOptions) *claudeHooksResult {
	result := &claudeHooksResult{FilePath: "Claude Code aweb-channel plugin"}
	if _, err := exec.LookPath("claude"); err != nil {
		if opts.RequireClaude {
			result.Error = fmt.Errorf("claude is required to install the aweb-channel plugin; install Claude Code and try again")
		} else {
			result.Skipped = true
		}
		return result
	}
	if err := runClaudeChannelPluginCommand("plugin", "marketplace", "add", claudeChannelMarketplace); err != nil {
		result.Error = fmt.Errorf("claude plugin marketplace add %s: %w", claudeChannelMarketplace, err)
		return result
	}
	if err := runClaudeChannelPluginCommand("plugin", "install", claudeChannelPlugin); err != nil {
		result.Error = fmt.Errorf("claude plugin install %s: %w", claudeChannelPlugin, err)
		return result
	}
	result.Created = true
	return result
}

func EnsurePiChannelExtension() *claudeHooksResult {
	result := &claudeHooksResult{FilePath: "Pi aweb channel extension"}
	if _, err := exec.LookPath("pi"); err != nil {
		result.Error = fmt.Errorf("pi is required to install the aweb channel extension; install pi and try again")
		return result
	}
	if present, err := piChannelExtensionInstalled(); err != nil {
		result.Error = err
		return result
	} else if present {
		result.AlreadyExists = true
		return result
	}
	if output, err := runPiChannelExtensionCommand("install", piChannelExtensionSource, "--no-approve"); err != nil {
		result.Error = fmt.Errorf("pi install %s --no-approve: %w%s", piChannelExtensionSource, err, formatCommandOutput(output))
		return result
	}
	if present, err := piChannelExtensionInstalled(); err != nil {
		result.Error = err
		return result
	} else if !present {
		result.Error = fmt.Errorf("pi install %s completed but `pi list --no-approve` did not show %s", piChannelExtensionSource, piChannelExtensionPackage)
		return result
	}
	result.Created = true
	return result
}

func piChannelExtensionInstalled() (bool, error) {
	output, err := runPiChannelExtensionCommand("list", "--no-approve")
	if err != nil {
		return false, fmt.Errorf("pi list --no-approve: %w%s", err, formatCommandOutput(output))
	}
	return piChannelExtensionPresent(string(output)), nil
}

func piChannelExtensionPresent(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		field := strings.TrimSpace(line)
		if field == piChannelExtensionPackage || field == piChannelExtensionSource || strings.HasPrefix(field, piChannelExtensionPackage+"@") {
			return true
		}
	}
	return false
}

func formatCommandOutput(output []byte) string {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return ""
	}
	return ": " + text
}

// SetupChannelMCP is retained as the setup hook called by init/materialization,
// but it no longer writes .mcp.json. The working channel path is the Claude Code
// plugin, installed idempotently when Claude Code is available.
func SetupChannelMCP(repoRoot string, askConfirmation bool) *claudeHooksResult {
	result := &claudeHooksResult{FilePath: filepath.Join(repoRoot, ".mcp.json")}
	if askConfirmation {
		answer, err := promptString(
			"Set up Claude Code aweb-channel plugin for real-time coordination?\n"+
				"  (Requires starting Claude Code with: claude --dangerously-load-development-channels "+claudeChannelSpec+")\n"+
				"  (y/n)", "y")
		if err != nil {
			result.Error = err
			result.Skipped = true
			return result
		}
		normalized := strings.ToLower(strings.TrimSpace(answer))
		if normalized != "y" && normalized != "yes" {
			result.Skipped = true
			return result
		}
	}
	pluginResult := EnsureClaudeChannelPlugin(channelPluginOptions{RequireClaude: false})
	pluginResult.FilePath = result.FilePath
	return pluginResult
}

func printChannelMCPResult(result *claudeHooksResult) {
	if result == nil {
		return
	}
	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set up Claude Code aweb-channel plugin: %v\n", result.Error)
		printManualChannelInstructions()
		return
	}
	if result.Skipped {
		fmt.Println("Claude Code aweb-channel plugin: skipped")
		printManualChannelInstructions()
		return
	}
	if result.Created || result.Updated || result.AlreadyExists {
		fmt.Println("Claude Code aweb-channel plugin: installed or already present")
		printChannelStartInstructions()
	}
}

func printChannelStartInstructions() {
	fmt.Println("  Start Claude Code with:")
	fmt.Println("    claude --dangerously-load-development-channels " + claudeChannelSpec)
}

func printManualChannelInstructions() {
	fmt.Println()
	fmt.Println("To enable the aweb channel for Claude Code, install the plugin:")
	fmt.Println("    claude plugin marketplace add " + claudeChannelMarketplace)
	fmt.Println("    claude plugin install " + claudeChannelPlugin)
	printChannelStartInstructions()
}
