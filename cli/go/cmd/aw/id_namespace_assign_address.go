package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idNamespaceAssignAddressOutput struct {
	Status        string `json:"status"`
	Address       string `json:"address"`
	Domain        string `json:"domain"`
	Name          string `json:"name"`
	DIDAW         string `json:"did_aw"`
	DIDKey        string `json:"did_key"`
	Reachability  string `json:"reachability"`
	ControllerDID string `json:"controller_did"`
	RegistryURL   string `json:"registry_url"`
}

type idNamespaceAssignAddressOptions struct {
	Domain          string
	Name            string
	DIDAW           string
	Reachability    string
	VisibleToTeamID string
}

var (
	idNamespaceAssignAddressDomain          string
	idNamespaceAssignAddressName            string
	idNamespaceAssignAddressDIDAW           string
	idNamespaceAssignAddressReachability    string
	idNamespaceAssignAddressVisibleToTeamID string
	idNamespaceAssignAddressCmd             = &cobra.Command{
		Use:   "assign-address",
		Short: "Assign a namespace address to an existing did:aw using the local controller key",
		RunE:  runIDNamespaceAssignAddress,
	}
)

func init() {
	idNamespaceAssignAddressCmd.Flags().StringVar(&idNamespaceAssignAddressDomain, "domain", "", "Namespace domain (e.g. aweb.ai)")
	idNamespaceAssignAddressCmd.Flags().StringVar(&idNamespaceAssignAddressName, "name", "", "Address name (e.g. alice)")
	idNamespaceAssignAddressCmd.Flags().StringVar(&idNamespaceAssignAddressDIDAW, "did-aw", "", "Existing did:aw to bind the address to")
	idNamespaceAssignAddressCmd.Flags().StringVar(&idNamespaceAssignAddressReachability, "reachability", "public", "Address reachability (public|nobody|org_only|team_members_only)")
	idNamespaceAssignAddressCmd.Flags().StringVar(&idNamespaceAssignAddressVisibleToTeamID, "visible-to-team-id", "", "Required when reachability=team_members_only")
	idNamespaceCmd.AddCommand(idNamespaceAssignAddressCmd)
}

func runIDNamespaceAssignAddress(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeIDNamespaceAssignAddress(ctx, idNamespaceAssignAddressOptions{
		Domain:          idNamespaceAssignAddressDomain,
		Name:            idNamespaceAssignAddressName,
		DIDAW:           idNamespaceAssignAddressDIDAW,
		Reachability:    idNamespaceAssignAddressReachability,
		VisibleToTeamID: idNamespaceAssignAddressVisibleToTeamID,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespaceAssignAddress)
	return nil
}

func executeIDNamespaceAssignAddress(ctx context.Context, opts idNamespaceAssignAddressOptions) (idNamespaceAssignAddressOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, err
	}
	name, err := normalizeIDCreateName(opts.Name)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, err
	}
	didAW := strings.TrimSpace(opts.DIDAW)
	if !strings.HasPrefix(didAW, "did:aw:") || strings.TrimSpace(strings.TrimPrefix(didAW, "did:aw:")) == "" {
		return idNamespaceAssignAddressOutput{}, usageError("--did-aw must be a non-empty did:aw: identifier")
	}
	reachability := strings.TrimSpace(opts.Reachability)
	if reachability == "" {
		reachability = "public"
	}
	visibleToTeamID := strings.TrimSpace(opts.VisibleToTeamID)
	if reachability == "team_members_only" && visibleToTeamID == "" {
		return idNamespaceAssignAddressOutput{}, usageError("--visible-to-team-id is required when reachability=team_members_only")
	}
	if reachability != "team_members_only" && visibleToTeamID != "" {
		return idNamespaceAssignAddressOutput{}, usageError("--visible-to-team-id is only valid when reachability=team_members_only")
	}

	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, err
	}
	if !exists {
		keyPath, _ := awconfig.ControllerKeyPath(domain)
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("no controller key for domain %q (expected at %s); import the controller seed before assigning addresses", domain, keyPath)
	}
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("load controller key for %s: %w", domain, err)
	}
	expectedControllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

	registry, err := newRegistryClientWithPreferredBaseURL("")
	if err != nil {
		return idNamespaceAssignAddressOutput{}, err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("discover registry for %s: %w", domain, err)
	}

	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("fetch namespace %s: %w", domain, err)
	}
	if strings.TrimSpace(namespace.ControllerDID) != expectedControllerDID {
		return idNamespaceAssignAddressOutput{}, fmt.Errorf(
			"local controller key for %s does not match registered controller (local=%s, registry=%s)",
			domain, expectedControllerDID, namespace.ControllerDID,
		)
	}

	resolution, err := registry.ResolveKeyAt(ctx, registryURL, didAW)
	if err != nil {
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("resolve current did:key for %s: %w", didAW, err)
	}
	currentDIDKey := strings.TrimSpace(resolution.CurrentDIDKey)
	if currentDIDKey == "" {
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("registry returned no current did:key for %s", didAW)
	}

	address, err := registry.RegisterAddressAt(ctx, registryURL, domain, name, didAW, currentDIDKey, reachability, controllerKey, visibleToTeamID)
	if err != nil {
		var regErr *awid.RegistryError
		if errors.As(err, &regErr) && regErr.StatusCode == http.StatusConflict {
			existing, _, getErr := registry.GetNamespaceAddressAt(ctx, registryURL, domain, name)
			if getErr != nil {
				return idNamespaceAssignAddressOutput{}, fmt.Errorf("registry returned 409 for address %s/%s and lookup failed (%w); original conflict: %v", domain, name, getErr, regErr)
			}
			if strings.TrimSpace(existing.DIDAW) != didAW {
				return idNamespaceAssignAddressOutput{}, fmt.Errorf("address %s/%s is already assigned to %s (cannot reassign without dashboard Replace)", domain, name, existing.DIDAW)
			}
			existingDIDKey := strings.TrimSpace(existing.CurrentDIDKey)
			if existingDIDKey != currentDIDKey {
				return idNamespaceAssignAddressOutput{}, fmt.Errorf("address %s/%s is assigned to %s but resolves to did:key %s, not current did:key %s", domain, name, didAW, existingDIDKey, currentDIDKey)
			}
			return idNamespaceAssignAddressOutput{
				Status:        "already_assigned",
				Address:       fmt.Sprintf("%s/%s", domain, name),
				Domain:        domain,
				Name:          name,
				DIDAW:         existing.DIDAW,
				DIDKey:        existingDIDKey,
				Reachability:  strings.TrimSpace(existing.Reachability),
				ControllerDID: expectedControllerDID,
				RegistryURL:   registryURL,
			}, nil
		}
		return idNamespaceAssignAddressOutput{}, fmt.Errorf("register address %s/%s: %w", domain, name, err)
	}

	return idNamespaceAssignAddressOutput{
		Status:        "assigned",
		Address:       fmt.Sprintf("%s/%s", domain, name),
		Domain:        domain,
		Name:          name,
		DIDAW:         strings.TrimSpace(address.DIDAW),
		DIDKey:        strings.TrimSpace(address.CurrentDIDKey),
		Reachability:  strings.TrimSpace(address.Reachability),
		ControllerDID: expectedControllerDID,
		RegistryURL:   registryURL,
	}, nil
}

func formatIDNamespaceAssignAddress(v any) string {
	out := v.(idNamespaceAssignAddressOutput)
	var b strings.Builder
	switch out.Status {
	case "assigned":
		fmt.Fprintf(&b, "Assigned %s -> %s\n", out.Address, out.DIDAW)
	case "already_assigned":
		fmt.Fprintf(&b, "Address %s already assigned to %s (no changes)\n", out.Address, out.DIDAW)
	default:
		fmt.Fprintf(&b, "%s %s -> %s\n", out.Status, out.Address, out.DIDAW)
	}
	fmt.Fprintf(&b, "  did:key:       %s\n", out.DIDKey)
	fmt.Fprintf(&b, "  reachability:  %s\n", out.Reachability)
	fmt.Fprintf(&b, "  controller:    %s\n", out.ControllerDID)
	fmt.Fprintf(&b, "  registry:      %s\n", out.RegistryURL)
	return b.String()
}
