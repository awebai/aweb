package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// agentsListOutput wraps the server response with local config fields for display.
type agentsListOutput struct {
	*awid.ListIdentitiesResponse
	ProjectSlug string `json:"project_slug,omitempty"`
}

// identityPatchOutput wraps the server response with the identity alias for display.
type identityPatchOutput struct {
	*awid.PatchIdentityResponse
	Alias string `json:"alias,omitempty"`
}

// resolveCurrentIdentityID resolves the current identity's server ID via
// introspect.
func resolveCurrentIdentityID(ctx context.Context, client *aweb.Client, _ *awconfig.Selection) (string, error) {
	intro, err := client.Introspect(ctx)
	if err != nil {
		return "", err
	}
	if intro.IdentityID == "" {
		return "", fmt.Errorf("cannot determine identity id: API key is not bound to an identity")
	}
	return intro.IdentityID, nil
}

var identitiesCmd = &cobra.Command{
	Use:   "identities",
	Short: "List identities in the current project",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := client.ListIdentities(ctx)
		if err != nil {
			return err
		}
		printOutput(agentsListOutput{
			ListIdentitiesResponse: resp,
			ProjectSlug:            sel.NamespaceSlug,
		}, formatAgentsList)
		return nil
	},
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Identity lifecycle, settings, and key management",
}

var agentAccessModeCmd = &cobra.Command{
	Use:   "access-mode [open|contacts_only]",
	Short: "Get or set identity access mode",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		agentID, err := resolveCurrentIdentityID(ctx, client, sel)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			// GET: list agents, find self, print access_mode.
			identities, err := client.ListIdentities(ctx)
			if err != nil {
				return err
			}
			for _, a := range identities.Identities {
				if a.IdentityID == agentID {
					printOutput(map[string]string{
						"identity_id": a.IdentityID,
						"alias":       firstNonEmpty(a.Name, a.Alias),
						"access_mode": a.AccessMode,
					}, formatAgentAccessMode)
					return nil
				}
			}
			return fmt.Errorf("identity %s not found in identities list", agentID)
		}

		// SET: patch access mode.
		mode := args[0]
		if mode != "open" && mode != "contacts_only" {
			return fmt.Errorf("invalid access mode: %s (must be \"open\" or \"contacts_only\")", mode)
		}

		resp, err := client.PatchIdentity(ctx, agentID, &awid.PatchIdentityRequest{
			AccessMode: mode,
		})
		if err != nil {
			return err
		}
		printOutput(identityPatchOutput{
			PatchIdentityResponse: resp,
			Alias:                 sel.IdentityHandle,
		}, formatAgentPatch)
		return nil
	},
}

var identityReachabilityCmd = &cobra.Command{
	Use:   "reachability [private|org-visible|contacts-only|public]",
	Short: "Get or set permanent address reachability",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		lifetime, _, err := resolveSelectionIdentityState(ctx, client, sel)
		if err != nil {
			return err
		}
		if awid.IdentityClassFromLifetime(lifetime) != awid.IdentityClassPermanent {
			return fmt.Errorf("reachability is only defined for permanent identities")
		}
		agentID, err := resolveCurrentIdentityID(ctx, client, sel)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			identities, err := client.ListIdentities(ctx)
			if err != nil {
				return err
			}
			for _, a := range identities.Identities {
				if a.IdentityID == agentID {
					printOutput(map[string]string{
						"identity_id":          a.IdentityID,
						"alias":                firstNonEmpty(a.Name, a.Alias),
						"address_reachability": a.AddressReachability,
					}, formatIdentityReachability)
					return nil
				}
			}
			return fmt.Errorf("identity %s not found in identities list", agentID)
		}

		reachability := normalizeAddressReachability(args[0])
		if reachability == "" {
			return fmt.Errorf("invalid reachability: %s (must be \"private\", \"org-visible\", \"contacts-only\", or \"public\")", args[0])
		}

		resp, err := client.PatchIdentity(ctx, agentID, &awid.PatchIdentityRequest{
			AddressReachability: reachability,
		})
		if err != nil {
			return err
		}
		printOutput(identityPatchOutput{
			PatchIdentityResponse: resp,
			Alias:                 sel.IdentityHandle,
		}, formatAgentPatch)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(identitiesCmd)
	identityCmd.AddCommand(agentAccessModeCmd)
	identityCmd.AddCommand(identityReachabilityCmd)
	rootCmd.AddCommand(identityCmd)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
