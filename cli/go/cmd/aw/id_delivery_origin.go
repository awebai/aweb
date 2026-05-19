package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idDeliveryOriginOptions struct {
	DIDAW  string
	Origin string
}

type idDeliveryOriginOutput struct {
	Status        string `json:"status"`
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
	Origin        string `json:"origin"`
	RegistryURL   string `json:"registry_url"`
}

var (
	idDeliveryOriginDIDAW  string
	idDeliveryOriginOrigin string
	idDeliveryOriginCmd    = &cobra.Command{
		Use:   "set-delivery-origin",
		Short: "Set the current did:aw delivery origin using the identity key",
		Args:  cobra.NoArgs,
		RunE:  runIDDeliveryOrigin,
	}
)

func init() {
	idDeliveryOriginCmd.Flags().StringVar(&idDeliveryOriginDIDAW, "did-aw", "", "did:aw identity to update (defaults to the current identity)")
	idDeliveryOriginCmd.Flags().StringVar(&idDeliveryOriginOrigin, "origin", "", "Canonical aweb server origin (e.g. https://aweb.acme.com)")
	identityCmd.AddCommand(idDeliveryOriginCmd)
}

func runIDDeliveryOrigin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeIDDeliveryOrigin(ctx, idDeliveryOriginOptions{
		DIDAW:  idDeliveryOriginDIDAW,
		Origin: idDeliveryOriginOrigin,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDDeliveryOrigin)
	return nil
}

func executeIDDeliveryOrigin(ctx context.Context, opts idDeliveryOriginOptions) (idDeliveryOriginOutput, error) {
	identity, err := resolveIdentity()
	if err != nil {
		return idDeliveryOriginOutput{}, err
	}
	signingKey, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return idDeliveryOriginOutput{}, err
	}
	if err := requirePersistentSelfCustodialIdentity(identity, signingKey); err != nil {
		return idDeliveryOriginOutput{}, err
	}
	didAW := strings.TrimSpace(opts.DIDAW)
	if didAW == "" {
		didAW = strings.TrimSpace(identity.StableID)
	}
	if !strings.HasPrefix(didAW, "did:aw:") {
		return idDeliveryOriginOutput{}, usageError("--did-aw must start with did:aw:")
	}
	if didAW != strings.TrimSpace(identity.StableID) {
		return idDeliveryOriginOutput{}, usageError("--did-aw must match the current self-custodial identity")
	}
	origin, err := awid.CanonicalServerOrigin(opts.Origin)
	if err != nil {
		return idDeliveryOriginOutput{}, fmt.Errorf("--origin: %w", err)
	}

	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return idDeliveryOriginOutput{}, err
	}
	registryURL, err := currentIdentityRegistryURL(ctx, identity, registry)
	if err != nil {
		return idDeliveryOriginOutput{}, err
	}
	mapping, err := registry.SetDIDDeliveryOriginAt(ctx, registryURL, didAW, origin, signingKey)
	if err != nil {
		return idDeliveryOriginOutput{}, fmt.Errorf("set delivery origin for %s: %w", didAW, err)
	}
	if mapping == nil {
		return idDeliveryOriginOutput{}, fmt.Errorf("registry returned no did mapping")
	}
	return idDeliveryOriginOutput{
		Status:        "updated",
		DIDAW:         strings.TrimSpace(mapping.DIDAW),
		CurrentDIDKey: strings.TrimSpace(mapping.CurrentDIDKey),
		Origin:        strings.TrimSpace(mapping.DeliveryOrigin),
		RegistryURL:   registryURL,
	}, nil
}

func formatIDDeliveryOrigin(v any) string {
	out := v.(idDeliveryOriginOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Set delivery origin for %s to %s\n", out.DIDAW, out.Origin)
	fmt.Fprintf(&b, "  did:key:  %s\n", out.CurrentDIDKey)
	fmt.Fprintf(&b, "  registry: %s\n", out.RegistryURL)
	return b.String()
}
