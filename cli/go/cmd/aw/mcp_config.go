package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	mcpConfigChannel bool
)

var mcpConfigCmd = &cobra.Command{
	Use:   "mcp-config",
	Short: "Output MCP server configuration for the current identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mcpConfigChannel {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			cfg := channelMCPConfig(wd)
			out, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal config: %w", err)
			}
			fmt.Println(string(out))
			return nil
		}

		return usageError("HTTP MCP config is not emitted by this command because /mcp now requires per-request DIDKey signatures plus a team certificate; use `aw mcp-config --channel`")
	},
}

func channelMCPConfig(cwd string) map[string]any {
	return map[string]any{
		"mcpServers": map[string]any{
			"aweb": map[string]any{
				"command": "npx",
				"args":    []string{"@awebai/claude-channel"},
				"cwd":     cwd,
			},
		},
	}
}

func init() {
	mcpConfigCmd.Flags().BoolVar(&mcpConfigChannel, "channel", false, "Output stdio channel config instead of HTTP MCP config")
	rootCmd.AddCommand(mcpConfigCmd)
}
