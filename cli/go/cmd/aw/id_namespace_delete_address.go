package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idNamespaceDeleteAddressOutput struct {
	Status        string `json:"status"`
	Address       string `json:"address"`
	Domain        string `json:"domain"`
	Name          string `json:"name"`
	ControllerDID string `json:"controller_did"`
	RegistryURL   string `json:"registry_url"`
}

type idNamespaceDeleteAddressOptions struct {
	Domain      string
	Name        string
	RegistryURL string
	Reason      string
}

var (
	idNamespaceDeleteAddressDomain   string
	idNamespaceDeleteAddressName     string
	idNamespaceDeleteAddressRegistry string
	idNamespaceDeleteAddressReason   string
	idNamespaceDeleteAddressCmd      = &cobra.Command{
		Use:   "delete-address",
		Short: "Delete a namespace address claim using the local controller key",
		Long: "Delete a namespace address claim using the local namespace controller key.\n\n" +
			"This removes the address route/claim, not the append-only did:aw audit log. If the\n" +
			"address has active team certificates, revoke those certificates first.",
		RunE: runIDNamespaceDeleteAddress,
	}
)

func init() {
	idNamespaceDeleteAddressCmd.Flags().StringVar(&idNamespaceDeleteAddressDomain, "domain", "", "Namespace domain (e.g. aweb.ai)")
	idNamespaceDeleteAddressCmd.Flags().StringVar(&idNamespaceDeleteAddressName, "name", "", "Address name (e.g. alice)")
	idNamespaceDeleteAddressCmd.Flags().StringVar(&idNamespaceDeleteAddressRegistry, "registry", "", "Registry origin override")
	idNamespaceDeleteAddressCmd.Flags().StringVar(&idNamespaceDeleteAddressReason, "reason", "", "Optional deletion reason recorded by the registry")
	idNamespaceCmd.AddCommand(idNamespaceDeleteAddressCmd)
}

func runIDNamespaceDeleteAddress(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeIDNamespaceDeleteAddress(ctx, idNamespaceDeleteAddressOptions{
		Domain:      idNamespaceDeleteAddressDomain,
		Name:        idNamespaceDeleteAddressName,
		RegistryURL: idNamespaceDeleteAddressRegistry,
		Reason:      idNamespaceDeleteAddressReason,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespaceDeleteAddress)
	return nil
}

func executeIDNamespaceDeleteAddress(ctx context.Context, opts idNamespaceDeleteAddressOptions) (idNamespaceDeleteAddressOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idNamespaceDeleteAddressOutput{}, err
	}
	name, err := normalizeIDCreateName(opts.Name)
	if err != nil {
		return idNamespaceDeleteAddressOutput{}, err
	}
	controllerKey, controllerDID, err := loadVerifiedNamespaceControllerKey(ctx, domain, opts.RegistryURL)
	if err != nil {
		return idNamespaceDeleteAddressOutput{}, err
	}

	registry, err := newRegistryClientWithPreferredBaseURL(opts.RegistryURL)
	if err != nil {
		return idNamespaceDeleteAddressOutput{}, err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return idNamespaceDeleteAddressOutput{}, fmt.Errorf("discover registry for %s: %w", domain, err)
	}

	if err := registry.DeleteAddressAt(ctx, registryURL, domain, name, controllerKey, opts.Reason); err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusConflict {
			return idNamespaceDeleteAddressOutput{}, fmt.Errorf("delete address %s/%s: active certificates exist; revoke team membership certificates first: %w", domain, name, err)
		}
		return idNamespaceDeleteAddressOutput{}, fmt.Errorf("delete address %s/%s: %w", domain, name, err)
	}

	return idNamespaceDeleteAddressOutput{
		Status:        "deleted",
		Address:       fmt.Sprintf("%s/%s", domain, name),
		Domain:        domain,
		Name:          name,
		ControllerDID: controllerDID,
		RegistryURL:   registryURL,
	}, nil
}

func loadVerifiedNamespaceControllerKey(ctx context.Context, domain, registryOverride string) (ed25519.PrivateKey, string, error) {
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, "", err
	}
	if !exists {
		keyPath, _ := awconfig.ControllerKeyPath(domain)
		return nil, "", fmt.Errorf("no controller key for domain %q (expected at %s)", domain, keyPath)
	}
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return nil, "", fmt.Errorf("load controller key for %s: %w", domain, err)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

	registry, err := newRegistryClientWithPreferredBaseURL(registryOverride)
	if err != nil {
		return nil, "", err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", fmt.Errorf("discover registry for %s: %w", domain, err)
	}
	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return nil, "", fmt.Errorf("fetch namespace %s: %w", domain, err)
	}
	if strings.TrimSpace(namespace.ControllerDID) != controllerDID {
		return nil, "", fmt.Errorf(
			"local controller key for %s does not match registered controller (local=%s, registry=%s)",
			domain, controllerDID, namespace.ControllerDID,
		)
	}
	return controllerKey, controllerDID, nil
}

func formatIDNamespaceDeleteAddress(v any) string {
	out := v.(idNamespaceDeleteAddressOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Deleted address claim %s\n", out.Address)
	fmt.Fprintf(&b, "  controller:    %s\n", out.ControllerDID)
	fmt.Fprintf(&b, "  registry:      %s\n", out.RegistryURL)
	return b.String()
}
