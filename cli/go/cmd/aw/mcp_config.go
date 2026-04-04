package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

		sel, err := resolveSelectionForDir("")
		if err != nil {
			return err
		}

		baseURL := strings.TrimRight(sel.BaseURL, "/")

		cfg := map[string]any{
			"mcpServers": map[string]any{
				"aweb": map[string]any{
					"url": baseURL + "/mcp",
					"headers": map[string]string{
						"Authorization": "Bearer " + sel.APIKey,
					},
				},
			},
		}

		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		fmt.Println(string(out))
		return nil
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
