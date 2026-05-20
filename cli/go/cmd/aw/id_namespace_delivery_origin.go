package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idNamespaceDeliveryOriginOptions struct {
	Domain string
	Origin string
}

type idNamespaceDeliveryOriginOutput struct {
	Status        string `json:"status"`
	Domain        string `json:"domain"`
	Origin        string `json:"origin"`
	ControllerDID string `json:"controller_did"`
	RegistryURL   string `json:"registry_url"`
}

var (
	idNamespaceDeliveryOriginDomain string
	idNamespaceDeliveryOriginOrigin string
	idNamespaceDeliveryOriginCmd    = &cobra.Command{
		Use:   "set-delivery-origin",
		Short: "Set namespace address-route default delivery origin using the local controller key",
		RunE:  runIDNamespaceDeliveryOrigin,
	}
)

func init() {
	idNamespaceDeliveryOriginCmd.Flags().StringVar(&idNamespaceDeliveryOriginDomain, "namespace", "", "Namespace domain (e.g. acme.com)")
	idNamespaceDeliveryOriginCmd.Flags().StringVar(&idNamespaceDeliveryOriginDomain, "domain", "", "Namespace domain (alias for --namespace)")
	idNamespaceDeliveryOriginCmd.Flags().StringVar(&idNamespaceDeliveryOriginOrigin, "origin", "", "Canonical aweb server origin (e.g. https://aweb.acme.com)")
	idNamespaceCmd.AddCommand(idNamespaceDeliveryOriginCmd)
}

func runIDNamespaceDeliveryOrigin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeIDNamespaceDeliveryOrigin(ctx, idNamespaceDeliveryOriginOptions{
		Domain: idNamespaceDeliveryOriginDomain,
		Origin: idNamespaceDeliveryOriginOrigin,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespaceDeliveryOrigin)
	return nil
}

func executeIDNamespaceDeliveryOrigin(ctx context.Context, opts idNamespaceDeliveryOriginOptions) (idNamespaceDeliveryOriginOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, err
	}
	origin, err := awid.CanonicalServerOrigin(opts.Origin)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf("--origin: %w", err)
	}

	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, err
	}
	if !exists {
		keyPath, _ := awconfig.ControllerKeyPath(domain)
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf("no controller key for domain %q (expected at %s); import the controller seed before setting delivery origin", domain, keyPath)
	}
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf("load controller key for %s: %w", domain, err)
	}
	expectedControllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

	registry, err := newRegistryClientWithPreferredBaseURL("")
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf("discover registry for %s: %w", domain, err)
	}

	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf("fetch namespace %s: %w", domain, err)
	}
	if strings.TrimSpace(namespace.ControllerDID) != expectedControllerDID {
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf(
			"local controller key for %s does not match registered controller (local=%s, registry=%s)",
			domain, expectedControllerDID, namespace.ControllerDID,
		)
	}
	if strings.TrimSpace(namespace.DefaultDeliveryOrigin) == origin {
		return idNamespaceDeliveryOriginOutput{
			Status:        "unchanged",
			Domain:        domain,
			Origin:        origin,
			ControllerDID: expectedControllerDID,
			RegistryURL:   registryURL,
		}, nil
	}

	updated, err := registry.UpdateNamespaceDeliveryOriginAt(ctx, registryURL, domain, controllerKey, origin)
	if err != nil {
		return idNamespaceDeliveryOriginOutput{}, fmt.Errorf("set delivery origin for %s: %w", domain, err)
	}
	return idNamespaceDeliveryOriginOutput{
		Status:        "updated",
		Domain:        domain,
		Origin:        strings.TrimSpace(updated.DefaultDeliveryOrigin),
		ControllerDID: expectedControllerDID,
		RegistryURL:   registryURL,
	}, nil
}

func formatIDNamespaceDeliveryOrigin(v any) string {
	out := v.(idNamespaceDeliveryOriginOutput)
	var b strings.Builder
	switch out.Status {
	case "unchanged":
		fmt.Fprintf(&b, "Delivery origin for %s is already %s\n", out.Domain, out.Origin)
	default:
		fmt.Fprintf(&b, "Set delivery origin for %s to %s\n", out.Domain, out.Origin)
	}
	fmt.Fprintf(&b, "  controller: %s\n", out.ControllerDID)
	fmt.Fprintf(&b, "  registry:   %s\n", out.RegistryURL)
	return b.String()
}
