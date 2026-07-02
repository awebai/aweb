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
)

var runClaudeChannelPluginCommand = runClaudeChannelPluginCommandExec

func runClaudeChannelPluginCommandExec(args ...string) error {
	cmd := exec.Command("claude", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
