package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idAddressClaimOutput struct {
	Status        string `json:"status"`
	Address       string `json:"address"`
	Domain        string `json:"domain"`
	Name          string `json:"name"`
	DIDAW         string `json:"did_aw"`
	DIDKey        string `json:"did_key"`
	ControllerDID string `json:"controller_did"`
	RegistryURL   string `json:"registry_url"`
}

type idAddressClaimOptions struct {
	Address     string
	RegistryURL string
}

var (
	idAddressClaimRegistryURL string
	idAddressCmd              = &cobra.Command{
		Use:   "address",
		Short: "Manage addresses for the current global identity",
	}
	idAddressClaimCmd = &cobra.Command{
		Use:   "claim <namespace>/<name>",
		Short: "Claim an additional address for the current global identity",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDAddressClaim,
	}
)

func init() {
	idAddressClaimCmd.Flags().StringVar(&idAddressClaimRegistryURL, "registry", "", "Registry origin override")
	idAddressCmd.AddCommand(idAddressClaimCmd)
	identityCmd.AddCommand(idAddressCmd)
}

func runIDAddressClaim(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	workingDir, _ := os.Getwd()
	out, err := executeIDAddressClaim(ctx, workingDir, idAddressClaimOptions{
		Address:     args[0],
		RegistryURL: idAddressClaimRegistryURL,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDAddressClaim)
	return nil
}

func executeIDAddressClaim(ctx context.Context, workingDir string, opts idAddressClaimOptions) (idAddressClaimOutput, error) {
	domain, name, ok := awconfig.CutIdentityAddress(opts.Address)
	if !ok {
		return idAddressClaimOutput{}, usageError("address must be <namespace>/<name>")
	}
	domain, err := normalizeIDCreateDomain(domain, false)
	if err != nil {
		return idAddressClaimOutput{}, err
	}
	name, err = normalizeIDCreateName(name)
	if err != nil {
		return idAddressClaimOutput{}, err
	}
	address := domain + "/" + name

	identity, err := awconfig.ResolveIdentity(workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return idAddressClaimOutput{}, usageError("aw id address claim requires an existing global identity in this workspace; run `aw id create` first")
		}
		return idAddressClaimOutput{}, err
	}
	if strings.TrimSpace(identity.IdentityScope) != awid.IdentityModeGlobal || strings.TrimSpace(identity.StableID) == "" {
		return idAddressClaimOutput{}, usageError("aw id address claim requires an existing global identity in this workspace")
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return idAddressClaimOutput{}, usageError("aw id address claim requires a self-custodial global identity")
	}
	identityKey, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		return idAddressClaimOutput{}, fmt.Errorf("load identity signing key: %w", err)
	}
	identityDID := awid.ComputeDIDKey(identityKey.Public().(ed25519.PublicKey))
	if identityDID != strings.TrimSpace(identity.DID) {
		return idAddressClaimOutput{}, usageError("current signing key did:key %s does not match identity.yaml did %s", identityDID, identity.DID)
	}

	controllerKey, controllerDID, err := loadAddressClaimNamespaceController(domain)
	if err != nil {
		return idAddressClaimOutput{}, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return idAddressClaimOutput{}, err
	}
	registryURL, err := resolveAddressClaimRegistryURL(ctx, registry, domain, strings.TrimSpace(opts.RegistryURL), strings.TrimSpace(identity.RegistryURL))
	if err != nil {
		return idAddressClaimOutput{}, err
	}

	if _, err := registry.ClaimIdentityAddressAt(ctx, registryURL, awid.AtomicAddressClaimParams{
		Domain:                        domain,
		AddressName:                   name,
		DIDAW:                         strings.TrimSpace(identity.StableID),
		CurrentDIDKey:                 strings.TrimSpace(identity.DID),
		IdentitySigningKey:            identityKey,
		NamespaceControllerSigningKey: controllerKey,
		IdentityCustody:               string(awid.AddressClaimCustodySelf),
		NamespaceCustody:              string(awid.AddressClaimCustodySelf),
	}); err != nil {
		return idAddressClaimOutput{}, idAddressClaimAtomicError(address, registryURL, err)
	}

	return idAddressClaimOutput{
		Status:        "claimed",
		Address:       address,
		Domain:        domain,
		Name:          name,
		DIDAW:         strings.TrimSpace(identity.StableID),
		DIDKey:        strings.TrimSpace(identity.DID),
		ControllerDID: controllerDID,
		RegistryURL:   registryURL,
	}, nil
}

func loadAddressClaimNamespaceController(domain string) (ed25519.PrivateKey, string, error) {
	if isHostedAddressClaimDomain(domain) {
		return nil, "", usageError("namespace authority is required to claim %s; standalone hosted address claims are not supported. Join a hosted team with `aw id team accept-invite` or `aw team join` so aweb Cloud can claim the hosted address during accept.", domain)
	}
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, "", err
	}
	if !exists {
		keyPath, _ := awconfig.ControllerKeyPath(domain)
		return nil, "", usageError("namespace authority is required to claim %s; no local controller key found at %s", domain, keyPath)
	}
	key, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return nil, "", fmt.Errorf("load namespace controller key for %s: %w", domain, err)
	}
	return key, awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), nil
}

func resolveAddressClaimRegistryURL(ctx context.Context, registry *awid.RegistryClient, domain, override, identityRegistryURL string) (string, error) {
	if strings.TrimSpace(override) != "" {
		if err := registry.SetFallbackRegistryURL(override); err != nil {
			return "", fmt.Errorf("invalid --registry: %w", err)
		}
		return strings.TrimSpace(registry.DefaultRegistryURL), nil
	}
	if meta, err := awconfig.LoadControllerMeta(domain); err == nil && strings.TrimSpace(meta.RegistryURL) != "" {
		return strings.TrimSpace(meta.RegistryURL), nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err == nil && strings.TrimSpace(registryURL) != "" {
		return registryURL, nil
	}
	if strings.TrimSpace(identityRegistryURL) != "" {
		return strings.TrimSpace(identityRegistryURL), nil
	}
	if err != nil {
		return "", fmt.Errorf("discover registry for %s: %w", domain, err)
	}
	return "", fmt.Errorf("registry URL for %s is empty", domain)
}

func idAddressClaimAtomicError(address, registryURL string, err error) error {
	var conflict *awid.AtomicAddressClaimConflictError
	if errors.As(err, &conflict) {
		switch conflict.Code {
		case awid.AtomicAddressClaimCodeAddressTakenDifferentOwner:
			return usageError("address %s is already claimed by another identity; choose a different address name", address)
		case awid.AtomicAddressClaimCodeDIDTakenDifferentKey:
			return usageError("did:aw is already registered with a different key; restore the current identity signing key before retrying")
		case awid.AtomicAddressClaimCodeNamespaceAuthorityInvalid:
			return usageError("namespace authority for %s was rejected; restore the matching namespace controller key before retrying", address)
		case awid.AtomicAddressClaimCodeNamespaceNotRegistered:
			return usageError("namespace for %s is not registered at AWID; register the namespace before claiming addresses", address)
		case awid.AtomicAddressClaimCodePrimitiveDisabled, awid.AtomicAddressClaimCodePrimitiveNotSupported:
			return usageError("AWID server at %s does not support atomic address claims; upgrade awid-service before running `aw id address claim`", registryURL)
		default:
			return usageError("atomic address claim for %s failed with %s: %s", address, conflict.Code, strings.TrimSpace(conflict.Message))
		}
	}
	if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
		return usageError("AWID server at %s does not support atomic address claims; upgrade awid-service before running `aw id address claim`", registryURL)
	}
	if isRegistryUnavailableError(err) {
		return usageError("could not reach AWID registry at %s for atomic address claim; no local state was changed: %v", registryURL, err)
	}
	return err
}

func isHostedAddressClaimDomain(domain string) bool {
	domain = awconfig.NormalizeDomain(domain)
	return domain == "aweb.ai" || strings.HasSuffix(domain, ".aweb.ai")
}

func formatIDAddressClaim(v any) string {
	out := v.(idAddressClaimOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Claimed %s -> %s\n", out.Address, out.DIDAW)
	fmt.Fprintf(&b, "  did:key:       %s\n", out.DIDKey)
	fmt.Fprintf(&b, "  controller:    %s\n", out.ControllerDID)
	fmt.Fprintf(&b, "  registry:      %s\n", out.RegistryURL)
	return b.String()
}
