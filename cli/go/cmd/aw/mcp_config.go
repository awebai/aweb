package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var mcpConfigAll bool

var mcpConfigCmd = &cobra.Command{
	Use:   "mcp-config",
	Short: "Output MCP server configuration for the current identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mcpConfigAll {
			return mcpConfigAllAccounts()
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

func mcpConfigAllAccounts() error {
	global, err := awconfig.LoadGlobal()
	if err != nil {
		return err
	}

	servers := map[string]any{}
	for acctName, acct := range global.Accounts {
		srv, ok := global.Servers[acct.Server]
		if !ok || strings.TrimSpace(srv.URL) == "" {
			continue
		}
		baseURL := strings.TrimRight(srv.URL, "/")

		servers[acctName] = map[string]any{
			"url": baseURL + "/mcp",
			"headers": map[string]string{
				"Authorization": "Bearer " + acct.APIKey,
			},
		}
	}

	if len(servers) == 0 {
		return fmt.Errorf("no accounts with valid server URLs found in config")
	}

	cfg := map[string]any{"mcpServers": servers}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func init() {
	mcpConfigCmd.Flags().BoolVar(&mcpConfigAll, "all", false, "Output config for all accounts")
	rootCmd.AddCommand(mcpConfigCmd)
}
