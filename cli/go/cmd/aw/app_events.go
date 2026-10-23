package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
	"github.com/spf13/cobra"
)

// registerManifestEvents runs only for explicit management commands, after
// local resident approval. A receipt is saved only after every requested write
// succeeds. Failed registration can be retried with update; a partial initial
// subscription failure is retried by repeating install.
func registerManifestEvents(resolved *appmanifest.Resolved, fetchedDigest string, previous, next *pluginProvenance, update bool, selectedScopes []string) error {
	manifest := resolved.Manifest
	client, selection, err := resolveClientSelection()
	if err != nil {
		return fmt.Errorf("app events require a resident connected to a team: %w", err)
	}
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	var current appInstallationReceipt
	var expected *int64
	err = client.Get(ctx, "/v1/apps/"+url.PathEscape(manifest.App.ID)+"/installation?team_id="+url.QueryEscape(selection.TeamID), &current)
	if err != nil {
		var apiErr *awid.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
			return fmt.Errorf("read current app installation: %w", err)
		}
	} else {
		if current.InstallationID == "" || current.Generation <= 0 {
			return fmt.Errorf("installation_identity_required: the team server returned no installation identity")
		}
		expected = &current.Generation
	}
	grantedScopes, err := installationScopes(resolved.InstallScopes, current.GrantedScopes, expected != nil, selectedScopes)
	if err != nil {
		return err
	}
	reuse := current.State == "active" && current.OriginVerified && current.Digest == fetchedDigest &&
		(selectedScopes == nil || (update && previous != nil && slices.Equal(current.GrantedScopes, grantedScopes) && previous.RegisteredTeam == selection.TeamID && previous.RegisteredServer == selection.BaseURL))
	installed := current
	if !reuse {
		body := installRegistrationBody(resolved, fetchedDigest, expected, grantedScopes)
		if err := client.Post(ctx, "/v1/apps/install?team_id="+url.QueryEscape(selection.TeamID), body, &installed); err != nil {
			return fmt.Errorf("register app installation (existing local installation retained; request approval with aw plugin request %s): %w", manifest.App.Origin, err)
		}
	}
	if installed.InstallationID == "" || installed.Generation <= 0 || installed.State != "active" || !installed.OriginVerified || installed.Digest != fetchedDigest {
		return fmt.Errorf("installation_identity_required: the team server returned an invalid confirmation")
	}
	// Updates replace declarations and keys, but never reset the subscriber's
	// chosen intent. Only an explicit install creates the default subscriptions.
	if !update {
		for _, event := range installRegistrationEvents(manifest) {
			if err := client.Post(ctx, "/v1/events/subscriptions", map[string]any{
				"type":            manifest.App.ID + "/" + event.Type,
				"delivery_intent": event.DefaultDeliveryIntent,
			}, nil); err != nil {
				return fmt.Errorf("subscribe to %s/%s (registration retained; retry install): %w", manifest.App.ID, event.Type, err)
			}
		}
	}
	saveInstallationReceipt(next, installed, fetchedDigest, selection.TeamID, selection.BaseURL)
	return nil
}

func installRegistrationEvents(manifest appmanifest.Manifest) []appmanifest.Event {
	events := make([]appmanifest.Event, len(manifest.Events))
	copy(events, manifest.Events)
	for i := range events {
		events[i].Type = strings.TrimPrefix(strings.TrimSpace(events[i].Type), manifest.App.ID+"/")
	}
	return events
}

type appInstallationReceipt struct {
	InstallationID string   `json:"installation_id"`
	Generation     int64    `json:"generation"`
	State          string   `json:"state"`
	Digest         string   `json:"digest"`
	OriginVerified bool     `json:"origin_verified"`
	GrantedScopes  []string `json:"granted_scopes"`
}

func saveInstallationReceipt(next *pluginProvenance, receipt appInstallationReceipt, digest, team, server string) {
	next.RegisteredDigest, next.RegisteredTeam, next.RegisteredServer = digest, team, server
	next.RegisteredInstallationID, next.RegisteredGeneration = receipt.InstallationID, receipt.Generation
}

// installRegistrationBody confirms the fetched pin and explicitly chosen scopes.
// The server fetches its own bytes and derives versions, keys and events there.
// An expected generation comes from the authenticated current-installation read.
func installRegistrationBody(resolved *appmanifest.Resolved, fetchedDigest string, expectedGeneration *int64, grantedScopes []string) map[string]any {
	return map[string]any{
		"app_id": resolved.Manifest.App.ID, "origin": resolved.Manifest.App.Origin,
		"digest": fetchedDigest, "granted_scopes": append([]string{}, grantedScopes...),
		"expected_generation": expectedGeneration,
	}
}

func installationScopes(requested, current []string, existing bool, selected []string) ([]string, error) {
	chosen := selected
	if chosen == nil {
		chosen = requested
		if existing {
			chosen = nil
			for _, scope := range current {
				if slices.Contains(requested, scope) {
					chosen = append(chosen, scope)
				}
			}
		}
	}
	result := []string{}
	for _, scope := range chosen {
		scope = strings.TrimSpace(scope)
		if !slices.Contains(requested, scope) {
			return nil, usageError("scope_not_requested: %s is not requested by the manifest", scope)
		}
		if !slices.Contains(result, scope) {
			result = append(result, scope)
		}
	}
	slices.Sort(result)
	return result, nil
}

func init() {
	var intent, resource string
	cmd := &cobra.Command{
		Use: "subscribe <app/type>", Short: "Subscribe this resident to an installed app event", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if intent != "" && intent != "wake" && intent != "steer" && intent != "ambient" {
				return usageError("--intent must be wake, steer or ambient")
			}
			parts := strings.Split(args[0], "/")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return usageError("event type must be <app/type>")
			}
			_, resident, err := pluginManagementHome()
			if err != nil {
				return err
			}
			if !resident {
				return usageError("event subscriptions require a resident home")
			}
			client, err := resolveClient()
			if err != nil {
				return err
			}
			body := map[string]any{"type": args[0]}
			if cmd.Flags().Changed("intent") {
				body["delivery_intent"] = intent
			}
			if cmd.Flags().Changed("resource") {
				body["resource_ref"] = resource
			}
			ctx, cancel := commandAPIContext(cmd)
			defer cancel()
			var result map[string]any
			if err := client.Post(ctx, "/v1/events/subscriptions", body, &result); err != nil {
				return err
			}
			printOutput(result, func(v any) string {
				return fmt.Sprintf("Subscribed to %s (%s)\n", result["type"], result["delivery_intent"])
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&intent, "intent", "", "Delivery intent: wake, steer or ambient (default: app declaration)")
	cmd.Flags().StringVar(&resource, "resource", "", "Match only this resource reference")
	eventsCmd.AddCommand(cmd)
}
