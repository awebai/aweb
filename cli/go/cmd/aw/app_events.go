package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/awebai/aw/internal/appmanifest"
	"github.com/spf13/cobra"
)

// registerManifestEvents runs only for explicit management commands, after
// local resident approval. A receipt is saved only after every requested write
// succeeds. Failed registration can be retried with update; a partial initial
// subscription failure is retried by repeating install.
func registerManifestEvents(manifest appmanifest.Manifest, fetchedDigest string, previous, next *pluginProvenance, update bool) error {
	client, selection, err := resolveClientSelection()
	if err != nil {
		return fmt.Errorf("app events require a resident connected to a team: %w", err)
	}
	if update && previous != nil && previous.RegisteredDigest == fetchedDigest && previous.RegisteredTeam == selection.TeamID && previous.RegisteredServer == selection.BaseURL {
		next.RegisteredDigest, next.RegisteredTeam, next.RegisteredServer = previous.RegisteredDigest, previous.RegisteredTeam, previous.RegisteredServer
		return nil
	}
	events := make([]appmanifest.Event, len(manifest.Events))
	copy(events, manifest.Events)
	for i := range events {
		events[i].Type = strings.TrimPrefix(strings.TrimSpace(events[i].Type), manifest.App.ID+"/")
	}
	scopes := []string{}
	seen := map[string]bool{}
	for _, tool := range manifest.Tools {
		for _, scope := range tool.Scopes {
			if !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
		}
	}
	sort.Strings(scopes)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := map[string]any{
		"app_id": manifest.App.ID, "origin": manifest.App.Origin,
		"app_version": manifest.App.Version, "manifest_version": manifest.ManifestVersion,
		"digest": fetchedDigest, "granted_scopes": scopes,
		"events": events, "event_emitters": append([]appmanifest.EventEmitter{}, manifest.EventEmitters...),
	}
	if err := client.Post(ctx, "/v1/apps/install", body, nil); err != nil {
		return fmt.Errorf("register app events (local approval retained; retry install/update): %w", err)
	}
	// Updates replace declarations and keys, but never reset the subscriber's
	// chosen intent. Only an explicit install creates the default subscriptions.
	if !update {
		for _, event := range events {
			if err := client.Post(ctx, "/v1/events/subscriptions", map[string]any{
				"type":            manifest.App.ID + "/" + event.Type,
				"delivery_intent": event.DefaultDeliveryIntent,
			}, nil); err != nil {
				return fmt.Errorf("subscribe to %s/%s (registration retained; retry install): %w", manifest.App.ID, event.Type, err)
			}
		}
	}
	next.RegisteredDigest, next.RegisteredTeam, next.RegisteredServer = fetchedDigest, selection.TeamID, selection.BaseURL
	return nil
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
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
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
