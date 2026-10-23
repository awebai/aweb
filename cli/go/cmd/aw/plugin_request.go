package main

import (
	"fmt"
	"net/url"

	"github.com/awebai/aw/internal/appmanifest"
	"github.com/spf13/cobra"
)

func init() {
	pluginCmd.AddCommand(&cobra.Command{
		Use:   "request <origin>",
		Short: "Ask a team administrator to install an app; grants no tools or scopes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := manifestBaseForSource(args[0])
			if err != nil {
				return err
			}
			variant, err := discoverManifest(base)
			if err != nil {
				return manifestError(err)
			}
			resolved, err := appmanifest.Load(variant.Bytes, reservedRootCommandNames())
			if err != nil {
				return manifestError(err)
			}
			declared, err := manifestBaseForSource(resolved.Manifest.App.Origin)
			if err != nil || declared != base {
				return fmt.Errorf("origin_verification_required: the manifest must declare the origin that served it")
			}
			client, selection, err := resolveClientSelection()
			if err != nil {
				return err
			}
			ctx, cancel := commandAPIContext(cmd)
			defer cancel()
			var requested struct {
				RequestID string `json:"request_id"`
				State     string `json:"state"`
			}
			if err := client.Post(ctx, "/v1/apps/requests?team_id="+url.QueryEscape(selection.TeamID), map[string]any{
				"app_id": resolved.Manifest.App.ID, "origin": resolved.Manifest.App.Origin,
				"digest": variant.Digest, "requested_scopes": append([]string{}, resolved.InstallScopes...),
			}, &requested); err != nil {
				return fmt.Errorf("request app installation: %w", err)
			}
			printOutput(requested, func(v any) string {
				return fmt.Sprintf("Installation requested: %s (%s). A team administrator must approve it.\n", requested.RequestID, requested.State)
			})
			return nil
		},
	})
}
