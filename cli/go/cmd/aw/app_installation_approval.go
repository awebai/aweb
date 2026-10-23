package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type installationApprovalRefusal struct{ Code, Message string }

func (e *installationApprovalRefusal) Error() string { return e.Code + ": " + e.Message }

func installationRecovery(origin, home, teamID string) []string {
	return []string{"aw", "--identity-home", home, "--team", teamID, "plugin", "install", origin}
}

func installationApprovalError(code, origin, home, teamID string) error {
	return &installationApprovalRefusal{Code: code, Message: fmt.Sprintf(
		"The team's installation approval is missing, inactive or changed. Re-approve with %s, then mint a new grant with %s and restart the worker using that new grant home.",
		formatShellCommand(installationRecovery(origin, home, teamID)),
		formatShellCommand([]string{"aw", "--identity-home", home, "--team", teamID, "id", "grant", "mint", "--bundle", "normal-agent", "--ttl", "1h", "--custody-socket", "auto", "--out", "<new-empty-grant-home>"}))}
}

// No cache: a custody signing decision must observe the current installation,
// including when the request would otherwise reuse a cached signed response.
func activeInstallation(ctx context.Context, client *aweb.Client, teamID, appID string) (appInstallationReceipt, error) {
	var current appInstallationReceipt
	if client == nil {
		return current, fmt.Errorf("app_installation_unavailable")
	}
	err := client.Get(ctx, "/v1/apps/"+url.PathEscape(appID)+"/installation?team_id="+url.QueryEscape(teamID), &current)
	if err != nil {
		var apiErr *awid.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return current, fmt.Errorf("app_installation_inactive")
		}
		return current, fmt.Errorf("app_installation_unavailable")
	}
	if current.State != "active" || !current.OriginVerified || strings.TrimSpace(current.InstallationID) == "" || current.Generation <= 0 {
		return current, fmt.Errorf("app_installation_inactive")
	}
	return current, nil
}

func bindGrantInstallations(ctx context.Context, client *aweb.Client, teamID, home string, explicit bool, apps map[string]grantAppSnapshot, skipped []skippedGrantApp) ([]skippedGrantApp, error) {
	for name, app := range apps {
		current, err := activeInstallation(ctx, client, teamID, name)
		code := ""
		if err != nil {
			code = err.Error()
		} else if !explicit && app.InstallationID != current.InstallationID {
			code = "app_installation_changed"
		}
		if code != "" {
			if explicit {
				return skipped, installationApprovalError(code, app.App.Origin, home, teamID)
			}
			delete(apps, name)
			skipped = append(skipped, skippedGrantApp{AppID: name, Code: code, Origin: app.App.Origin})
			continue
		}
		app.InstallationID = current.InstallationID
		apps[name] = app
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].AppID < skipped[j].AppID })
	for i := range skipped {
		if skipped[i].Origin != "" {
			skipped[i].RecoveryCommand = installationRecovery(skipped[i].Origin, home, teamID)
		}
	}
	return skipped, nil
}

func annotateInstallationApprovals(cmd *cobra.Command, plugins []pluginListItem) error {
	hasManifest := false
	for _, plugin := range plugins {
		if plugin.Kind == "manifest" {
			hasManifest = true
			break
		}
	}
	if !hasManifest {
		return nil
	}
	home, err := identityHomeForDir(mustGetwd())
	if err != nil {
		return err
	}
	// Listing local bytes is also available from a worker; its immutable
	// delegated snapshot is not the resident's approval catalog.
	if awconfig.IsGrantHome(home.Root) {
		return nil
	}
	catalog, err := loadAppApprovals(home.Root)
	if err != nil {
		return err
	}
	selection, selectionErr := resolveSelectionForDir(mustGetwd())
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	var client *aweb.Client
	if selectionErr == nil {
		client, _, _ = resolveClientForSelection(mustGetwd(), selection)
	}
	for i := range plugins {
		plugin := &plugins[i]
		if plugin.Kind != "manifest" {
			continue
		}
		plugin.ApprovalStatus, plugin.ApprovalCode = "needs_approval", "app_installation_approval_required"
		if selectionErr != nil {
			continue
		}
		approval := catalog.Installations[selection.TeamID][plugin.Name]
		origin := approval.Origin
		if origin == "" {
			origin = catalog.Apps[plugin.Name]
		}
		if origin != "" {
			plugin.RecoveryCommand = installationRecovery(origin, home.Root, selection.TeamID)
		}
		if approval.InstallationID == "" {
			continue
		}
		current, err := activeInstallation(ctx, client, selection.TeamID, plugin.Name)
		if err != nil {
			plugin.ApprovalCode = err.Error()
			if plugin.ApprovalCode == "app_installation_unavailable" {
				plugin.ApprovalStatus = "unavailable"
			}
			continue
		}
		if current.InstallationID != approval.InstallationID {
			plugin.ApprovalCode = "app_installation_changed"
			continue
		}
		if plugin.Provenance == nil || plugin.Provenance.Origin != approval.Origin {
			plugin.ApprovalCode = "app_origin_mismatch"
			continue
		}
		plugin.ApprovalStatus, plugin.ApprovalCode = "approved", ""
	}
	return nil
}
