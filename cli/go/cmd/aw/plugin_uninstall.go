package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

type pluginUninstallOutput struct {
	AppID string `json:"app_id"`
	appInstallationReceipt
}

func init() {
	var expected int64
	cmd := &cobra.Command{
		Use:   "uninstall <app-id>",
		Short: "Uninstall an app from the selected team's server installation",
		Long: "Uninstall an app from the selected team's server installation. Requires current install-admin authority.\n" +
			"Local plugin files and approvals are retained; use aw plugin remove for local removal only.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID := strings.ToLower(strings.TrimSpace(args[0]))
			if valid, _ := regexp.MatchString(`^[a-z][a-z0-9-]{0,62}$`, appID); !valid {
				return usageError("app_id_invalid: use the installed app id")
			}
			explicit := cmd.Flags().Changed("expected-generation")
			if explicit && expected <= 0 {
				return usageError("generation_invalid: --expected-generation must be positive")
			}
			client, selection, err := resolveClientSelection()
			if err != nil {
				return err
			}
			ctx, cancel := commandAPIContext(cmd)
			defer cancel()
			path := "/v1/apps/" + url.PathEscape(appID)
			query := "?team_id=" + url.QueryEscape(selection.TeamID)
			generation := expected
			if !explicit {
				var current appInstallationReceipt
				if err := client.Get(ctx, path+"/installation"+query, &current); err != nil {
					return fmt.Errorf("read current app installation: %w", err)
				}
				if current.InstallationID == "" || current.Generation <= 0 {
					return fmt.Errorf("installation_identity_required: the team server returned no installation identity")
				}
				generation = current.Generation
			}
			var result pluginUninstallOutput
			if err := client.Post(ctx, path+"/uninstall"+query, map[string]int64{"expected_generation": generation}, &result); err != nil {
				return fmt.Errorf("uninstall app installation: %w", err)
			}
			if result.AppID != appID || result.InstallationID == "" || result.State != "uninstalled" || result.Generation < generation {
				return fmt.Errorf("installation_identity_required: the team server returned an invalid uninstall receipt")
			}
			printOutput(result, func(value any) string {
				receipt := value.(pluginUninstallOutput)
				return fmt.Sprintf("Uninstalled %s from team %s (generation %d).\n", receipt.AppID, selection.TeamID, receipt.Generation)
			})
			return nil
		},
	}
	cmd.Flags().Int64Var(&expected, "expected-generation", 0, "Require this installation generation (default: read the team's current generation)")
	pluginCmd.AddCommand(cmd)
}
