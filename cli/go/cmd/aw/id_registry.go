package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idShowOutput struct {
	Alias                 string `json:"alias,omitempty"`
	Address               string `json:"address,omitempty"`
	DIDAW                 string `json:"did_aw,omitempty"`
	DIDKey                string `json:"did_key,omitempty"`
	Custody               string `json:"custody,omitempty"`
	Lifetime              string `json:"lifetime,omitempty"`
	RegistryStatus        string `json:"registry_status"`
	RegistryURL           string `json:"registry_url,omitempty"`
	RegistryCurrentDIDKey string `json:"registry_current_did_key,omitempty"`
	RegistryError         string `json:"registry_error,omitempty"`
}

type idRegisterOutput struct {
	Status        string `json:"status"`
	RegistryURL   string `json:"registry_url"`
	Address       string `json:"address,omitempty"`
	DIDAW         string `json:"did_aw"`
	DIDKey        string `json:"did_key"`
	CurrentDIDKey string `json:"current_did_key,omitempty"`
}

type idResolveOutput struct {
	DIDAW         string               `json:"did_aw"`
	CurrentDIDKey string               `json:"current_did_key"`
	RegistryURL   string               `json:"registry_url"`
	LogHead       *awid.DidKeyEvidence `json:"log_head,omitempty"`
}

type idVerifyOutput struct {
	DIDAW         string `json:"did_aw"`
	RegistryURL   string `json:"registry_url"`
	Status        string `json:"status"`
	EntryCount    int    `json:"entry_count,omitempty"`
	CurrentDIDKey string `json:"current_did_key,omitempty"`
	Error         string `json:"error,omitempty"`
}

type idNamespaceOutput struct {
	RegistryURL string                  `json:"registry_url"`
	Namespace   *awid.RegistryNamespace `json:"namespace,omitempty"`
	Addresses   []awid.RegistryAddress  `json:"addresses,omitempty"`
}

type idRotateOutput struct {
	Status      string `json:"status"`
	RegistryURL string `json:"registry_url,omitempty"`
	OldDID      string `json:"old_did,omitempty"`
	NewDID      string `json:"new_did,omitempty"`
}

var idRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register the current persistent identity at awid.ai",
	RunE:  runIDRegister,
}

var idShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current identity and registry status",
	RunE:  runIDShow,
}

var idResolveCmd = &cobra.Command{
	Use:   "resolve <did_aw>",
	Short: "Resolve a did:aw to its current did:key",
	Args:  cobra.ExactArgs(1),
	RunE:  runIDResolve,
}

var idVerifyCmd = &cobra.Command{
	Use:   "verify <did_aw>",
	Short: "Verify the full audit log for a did:aw",
	Args:  cobra.ExactArgs(1),
	RunE:  runIDVerify,
}

var idNamespaceCmd = &cobra.Command{
	Use:   "namespace <domain>",
	Short: "Inspect a namespace and its registered addresses",
	Args:  cobra.ExactArgs(1),
	RunE:  runIDNamespace,
}

func init() {
	identityCmd.AddCommand(idRegisterCmd)
	identityCmd.AddCommand(idShowCmd)
	identityCmd.AddCommand(idResolveCmd)
	identityCmd.AddCommand(idVerifyCmd)
	identityCmd.AddCommand(idNamespaceCmd)
}

func runIDRegister(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	identity, err := resolveIdentity()
	if err != nil {
		return err
	}
	signingKey, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return err
	}
	if err := requirePersistentSelfCustodialIdentity(identity, signingKey); err != nil {
		return err
	}
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return err
	}
	awebURL, err := resolveOptionalWorkspaceBaseURL()
	if err != nil {
		return err
	}
	registryURL, err := currentIdentityRegistryURL(ctx, identity, registry)
	if err != nil {
		return err
	}
	mapping, err := registry.RegisterDID(
		ctx,
		registryURL,
		awebURL,
		identity.Address,
		identity.Handle,
		identity.DID,
		identity.StableID,
		signingKey,
	)
	status := "registered"
	if already := new(awid.AlreadyRegisteredError); errors.As(err, &already) {
		if strings.TrimSpace(already.ExistingDIDKey) != identity.DID {
			return fmt.Errorf("did:aw %s is already registered to %s; investigate ownership before retrying", already.DIDAW, already.ExistingDIDKey)
		}
		status = "already_registered"
		mapping = &awid.DIDMapping{
			DIDAW:         identity.StableID,
			CurrentDIDKey: identity.DID,
			Server:        awebURL,
			Address:       identity.Address,
		}
	} else if err != nil {
		return err
	}
	printOutput(idRegisterOutput{
		Status:        status,
		RegistryURL:   registryURL,
		Address:       identity.Address,
		DIDAW:         identity.StableID,
		DIDKey:        identity.DID,
		CurrentDIDKey: strings.TrimSpace(mapping.CurrentDIDKey),
	}, formatIDRegister)
	return nil
}

func runIDShow(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identity, err := resolveIdentity()
	if err != nil {
		return err
	}
	out := idShowOutput{
		Alias:          identity.Handle,
		Address:        identity.Address,
		DIDAW:          identity.StableID,
		DIDKey:         identity.DID,
		Custody:        identity.Custody,
		Lifetime:       identity.Lifetime,
		RegistryStatus: "not_applicable",
	}
	if identity.Lifetime == awid.LifetimePersistent && strings.TrimSpace(identity.StableID) != "" {
		registry, regClientErr := resolveIdentityRegistryClient(identity)
		if regClientErr != nil {
			out.RegistryStatus = "unreachable"
			out.RegistryError = regClientErr.Error()
		} else {
			registryURL, regErr := currentIdentityRegistryURL(ctx, identity, registry)
			if regErr != nil {
				out.RegistryStatus = "unreachable"
				out.RegistryError = regErr.Error()
			} else {
				out.RegistryURL = registryURL
				resolution, err := registry.ResolveKeyAt(ctx, registryURL, identity.StableID)
				if err != nil {
					if code, ok := registryStatusCode(err); ok && code == 404 {
						out.RegistryStatus = "not_registered"
					} else {
						out.RegistryStatus = "unreachable"
						out.RegistryError = err.Error()
					}
				} else {
					out.RegistryStatus = "registered"
					out.RegistryCurrentDIDKey = strings.TrimSpace(resolution.CurrentDIDKey)
				}
			}
		}
	}
	printOutput(out, formatIDShow)
	return nil
}

func runIDResolve(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry, sel, err := resolveRegistryClientForLookup()
	if err != nil {
		return err
	}
	didAW := strings.TrimSpace(args[0])
	if !strings.HasPrefix(didAW, "did:aw:") {
		return usageError("did_aw must start with did:aw:")
	}
	registryURL, err := registryLookupURL(ctx, registry, sel, didAW)
	if err != nil {
		return err
	}
	resolution, err := registry.ResolveKeyAt(ctx, registryURL, didAW)
	if err != nil {
		return err
	}
	printOutput(idResolveOutput{
		DIDAW:         didAW,
		CurrentDIDKey: strings.TrimSpace(resolution.CurrentDIDKey),
		RegistryURL:   registryURL,
		LogHead:       resolution.LogHead,
	}, formatIDResolve)
	return nil
}

func runIDVerify(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry, sel, err := resolveRegistryClientForLookup()
	if err != nil {
		return err
	}
	didAW := strings.TrimSpace(args[0])
	if !strings.HasPrefix(didAW, "did:aw:") {
		return usageError("did_aw must start with did:aw:")
	}
	registryURL, err := registryLookupURL(ctx, registry, sel, didAW)
	if err != nil {
		return err
	}
	logEntries, err := registry.GetDIDLog(ctx, registryURL, didAW)
	if err != nil {
		printOutput(idVerifyOutput{
			DIDAW:       didAW,
			RegistryURL: registryURL,
			Status:      "UNREACHABLE",
			Error:       err.Error(),
		}, formatIDVerify)
		return nil
	}
	head, verifyErr := awid.VerifyDidLogEntries(didAW, logEntries, time.Now().UTC())
	if verifyErr != nil {
		printOutput(idVerifyOutput{
			DIDAW:       didAW,
			RegistryURL: registryURL,
			Status:      "BROKEN",
			EntryCount:  len(logEntries),
			Error:       verifyErr.Error(),
		}, formatIDVerify)
		return nil
	}
	printOutput(idVerifyOutput{
		DIDAW:         didAW,
		RegistryURL:   registryURL,
		Status:        "OK",
		EntryCount:    len(logEntries),
		CurrentDIDKey: head.CurrentDIDKey,
	}, formatIDVerify)
	return nil
}

func runIDNamespace(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry, _, err := resolveRegistryClientForLookup()
	if err != nil {
		return err
	}
	domain := strings.TrimSpace(args[0])
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return err
	}
	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return err
	}
	addresses, _, err := registry.ListNamespaceAddressesAt(ctx, registryURL, domain)
	if err != nil {
		return err
	}
	printOutput(idNamespaceOutput{
		RegistryURL: registryURL,
		Namespace:   namespace,
		Addresses:   addresses,
	}, formatIDNamespace)
	return nil
}

func requirePersistentSelfCustodialIdentity(identity *awconfig.ResolvedIdentity, signingKey ed25519.PrivateKey) error {
	if identity == nil {
		return fmt.Errorf("missing identity context")
	}
	if strings.TrimSpace(identity.Lifetime) != awid.LifetimePersistent {
		return usageError("this command requires a persistent identity")
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return usageError("this command requires a self-custodial identity")
	}
	if strings.TrimSpace(identity.StableID) == "" {
		return fmt.Errorf("current identity is missing a did:aw stable identifier")
	}
	if strings.TrimSpace(identity.DID) == "" {
		return fmt.Errorf("current identity is missing a did:key")
	}
	if signingKey == nil {
		return usageError("current identity has no local signing key")
	}
	return nil
}

func currentIdentityRegistryURL(ctx context.Context, identity *awconfig.ResolvedIdentity, registry *awid.RegistryClient) (string, error) {
	if identity == nil {
		return "", fmt.Errorf("missing identity context")
	}
	if registry == nil {
		return "", fmt.Errorf("missing registry client")
	}
	if strings.TrimSpace(identity.RegistryURL) != "" {
		return strings.TrimSpace(identity.RegistryURL), nil
	}
	if strings.TrimSpace(identity.Domain) != "" {
		return registry.DiscoverRegistry(ctx, identity.Domain)
	}
	return registry.DefaultRegistryURL, nil
}

func registryLookupURL(ctx context.Context, registry *awid.RegistryClient, sel *awconfig.Selection, didAW string) (string, error) {
	if registry == nil {
		return "", fmt.Errorf("missing registry client")
	}
	if sel != nil && strings.TrimSpace(sel.StableID) == strings.TrimSpace(didAW) {
		address := selectionAddress(sel)
		if domain, _, ok := awconfig.CutIdentityAddress(address); ok && strings.TrimSpace(domain) != "" {
			return registry.DiscoverRegistry(ctx, domain)
		}
	}
	return registry.DefaultRegistryURL, nil
}

func resolveRegistryClientForLookup() (*awid.RegistryClient, *awconfig.Selection, error) {
	wd, _ := os.Getwd()
	sel, err := resolveSelectionForDir(wd)
	if err == nil && strings.TrimSpace(sel.BaseURL) != "" {
		baseURL, baseErr := resolveAuthenticatedBaseURL(sel.BaseURL)
		if baseErr != nil {
			return nil, nil, baseErr
		}
		sel.BaseURL = baseURL
		registry, regErr := newConfiguredRegistryClient(nil, baseURL)
		return registry, sel, regErr
	}
	registry, regErr := newConfiguredRegistryClient(nil, strings.TrimSpace(os.Getenv("AWEB_URL")))
	if err == nil {
		return registry, sel, regErr
	}
	return registry, nil, regErr
}

func resolveIdentityRegistryClient(identity *awconfig.ResolvedIdentity) (*awid.RegistryClient, error) {
	baseURL, err := resolveOptionalWorkspaceBaseURL()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(baseURL) == "" && identity != nil {
		baseURL = strings.TrimSpace(identity.RegistryURL)
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = strings.TrimSpace(os.Getenv("AWEB_URL"))
	}
	return newConfiguredRegistryClient(nil, baseURL)
}

func resolveIdentitySigningKey(identity *awconfig.ResolvedIdentity) (ed25519.PrivateKey, error) {
	if identity == nil {
		return nil, fmt.Errorf("missing identity context")
	}
	if strings.TrimSpace(identity.SigningKeyPath) == "" {
		return nil, usageError("current identity has no local signing key")
	}
	priv, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	return priv, nil
}

func resolveOptionalWorkspaceBaseURL() (string, error) {
	sel, err := resolveSelectionForDir("")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(sel.BaseURL) == "" {
		return "", nil
	}
	return resolveAuthenticatedBaseURL(sel.BaseURL)
}

func registryStatusCode(err error) (int, bool) {
	var regErr *awid.RegistryError
	if !errors.As(err, &regErr) {
		return 0, false
	}
	return regErr.StatusCode, true
}
