package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/awebai/aw/internal/appmanifest"
	"github.com/spf13/cobra"
)

// registerManifestEvents runs only for explicit management commands, after
// local resident approval. A receipt is saved only after every requested write
// succeeds. Failed registration can be retried with update; a partial initial
// subscription failure is retried by repeating install.
func registerManifestEvents(resolved *appmanifest.Resolved, fetchedDigest string, fetchedBytes []byte, previous, next *pluginProvenance, update bool) error {
	manifest := resolved.Manifest
	client, selection, err := resolveClientSelection()
	if err != nil {
		return fmt.Errorf("app events require a resident connected to a team: %w", err)
	}
	if update && previous != nil && previous.RegisteredDigest == fetchedDigest && previous.RegisteredTeam == selection.TeamID && previous.RegisteredServer == selection.BaseURL {
		next.RegisteredDigest, next.RegisteredTeam, next.RegisteredServer = previous.RegisteredDigest, previous.RegisteredTeam, previous.RegisteredServer
		return nil
	}
	events := installRegistrationEvents(manifest)
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	body := installRegistrationBody(resolved, fetchedDigest, fetchedBytes)
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

func installRegistrationEvents(manifest appmanifest.Manifest) []appmanifest.Event {
	events := make([]appmanifest.Event, len(manifest.Events))
	copy(events, manifest.Events)
	for i := range events {
		events[i].Type = strings.TrimPrefix(strings.TrimSpace(events[i].Type), manifest.App.ID+"/")
	}
	return events
}

// installRegistrationBody is the team install request for a resolved
// manifest. It grants the scopes of the agent and surface tools install
// activates; a hook-only tool's scopes wait for owner activation. Its event
// emitters are the manifest's app-event keys, from event_emitters in version 1
// and app_keys in version 2. fetchedBytes, when present, are the exact bytes
// that hash to fetchedDigest; the server then takes declarations and keys from
// them and refuses fields that disagree.
func installRegistrationBody(resolved *appmanifest.Resolved, fetchedDigest string, fetchedBytes []byte) map[string]any {
	manifest := resolved.Manifest
	emitters := []appmanifest.EventEmitter{}
	for _, key := range resolved.AppKeysFor("app-event") {
		emitters = append(emitters, appmanifest.EventEmitter{KID: key.KID, DIDKey: key.DIDKey})
	}
	body := map[string]any{
		"app_id": manifest.App.ID, "origin": manifest.App.Origin,
		"app_version": manifest.App.Version, "manifest_version": manifest.ManifestVersion,
		"digest": fetchedDigest, "granted_scopes": append([]string{}, resolved.InstallScopes...),
		"events": installRegistrationEvents(manifest), "event_emitters": emitters,
	}
	if fetchedBytes != nil {
		body["manifest"] = base64.StdEncoding.EncodeToString(fetchedBytes)
	}
	return body
}

// registrationManifestBytesFor returns the fetched bytes when the server reads
// that manifest version and the bytes name the origin being registered. It
// returns nil for a version the server does not read from bytes yet, and when a
// dev-origin override registers the app at an origin its bytes do not declare;
// the install then registers its supplied fields as before.
func registrationManifestBytesFor(fetchedBytes []byte, manifestVersion int, declaredOrigin, registeredOrigin string) []byte {
	if manifestVersion != 1 {
		return nil
	}
	declared, err := canonicalAppOrigin(declaredOrigin)
	if err != nil {
		return nil
	}
	registered, err := canonicalAppOrigin(registeredOrigin)
	if err != nil || declared != registered {
		return nil
	}
	return fetchedBytes
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
