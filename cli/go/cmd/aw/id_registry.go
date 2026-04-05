package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
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

type currentIdentityContext struct {
	Client     *aweb.Client
	Selection  *awconfig.Selection
	Registry   *awid.RegistryClient
	Identity   *awid.ResolvedIdentity
	SigningKey ed25519.PrivateKey
	Address    string
	Domain     string
	Handle     string
	DID        string
	StableID   string
	Custody    string
	Lifetime   string
}

var idRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register the current permanent identity at awid.ai",
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

	current, err := resolveCurrentIdentityContext(ctx, true)
	if err != nil {
		return err
	}
	if err := requirePermanentSelfCustodial(current); err != nil {
		return err
	}
	registryURL, err := current.registryURL(ctx)
	if err != nil {
		return err
	}
	mapping, err := current.Registry.RegisterDID(
		ctx,
		registryURL,
		current.Selection.BaseURL,
		current.Address,
		current.Handle,
		current.DID,
		current.StableID,
		current.SigningKey,
	)
	status := "registered"
	if already := new(awid.AlreadyRegisteredError); errors.As(err, &already) {
		if strings.TrimSpace(already.ExistingDIDKey) != current.DID {
			return fmt.Errorf("did:aw %s is already registered to %s; investigate ownership before retrying", already.DIDAW, already.ExistingDIDKey)
		}
		status = "already_registered"
		mapping = &awid.DIDMapping{
			DIDAW:         current.StableID,
			CurrentDIDKey: current.DID,
			Server:        current.Selection.BaseURL,
			Address:       current.Address,
		}
	} else if err != nil {
		return err
	}
	printOutput(idRegisterOutput{
		Status:        status,
		RegistryURL:   registryURL,
		Address:       current.Address,
		DIDAW:         current.StableID,
		DIDKey:        current.DID,
		CurrentDIDKey: strings.TrimSpace(mapping.CurrentDIDKey),
	}, formatIDRegister)
	return nil
}

func runIDShow(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try the full server-backed path first; fall back to standalone identity.
	current, fullErr := resolveCurrentIdentityContext(ctx, false)
	if fullErr != nil {
		return runIDShowStandalone(ctx)
	}
	out := idShowOutput{
		Alias:          current.Handle,
		Address:        current.Address,
		DIDAW:          current.StableID,
		DIDKey:         current.DID,
		Custody:        current.Custody,
		Lifetime:       current.Lifetime,
		RegistryStatus: "not_applicable",
	}
	if current.Lifetime == awid.LifetimePersistent && strings.TrimSpace(current.StableID) != "" {
		registryURL, regErr := current.registryURL(ctx)
		if regErr != nil {
			out.RegistryStatus = "unreachable"
			out.RegistryError = regErr.Error()
		} else {
			out.RegistryURL = registryURL
			resolution, err := current.Registry.ResolveKeyAt(ctx, registryURL, current.StableID)
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
	printOutput(out, formatIDShow)
	return nil
}

// runIDShowStandalone handles aw id show for directories with identity.yaml
// but no workspace.yaml (standalone identity created by aw id create).
func runIDShowStandalone(ctx context.Context) error {
	sel, err := resolveSelectionForDir("")
	if err != nil {
		return err
	}
	out := idShowOutput{
		Alias:          sel.IdentityHandle,
		Address:        sel.Address,
		DIDAW:          sel.StableID,
		DIDKey:         sel.DID,
		Custody:        sel.Custody,
		Lifetime:       sel.Lifetime,
		RegistryStatus: "not_applicable",
	}
	if sel.Lifetime == awid.LifetimePersistent && strings.TrimSpace(sel.StableID) != "" {
		registry, regClientErr := newConfiguredRegistryClient(nil, "")
		if regClientErr != nil {
			out.RegistryStatus = "unreachable"
			out.RegistryError = regClientErr.Error()
		} else {
			registryURL := strings.TrimSpace(registry.DefaultRegistryURL)
			wd, _ := os.Getwd()
			if identity, _, identityErr := awconfig.LoadWorktreeIdentityFromDir(wd); identityErr == nil {
				if v := strings.TrimSpace(identity.RegistryURL); v != "" {
					registryURL = v
				}
			}
			out.RegistryURL = registryURL
			resolution, err := registry.ResolveKeyAt(ctx, registryURL, sel.StableID)
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

func resolveCurrentIdentityContext(ctx context.Context, requireSigning bool) (*currentIdentityContext, error) {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return nil, err
	}
	registry, err := newConfiguredRegistryClient(client.Client.HTTPClient(), sel.BaseURL)
	if err != nil {
		return nil, err
	}
	current := &currentIdentityContext{
		Client:    client,
		Selection: sel,
		Registry:  registry,
		DID:       strings.TrimSpace(sel.DID),
		StableID:  strings.TrimSpace(sel.StableID),
		Custody:   strings.TrimSpace(sel.Custody),
		Lifetime:  strings.TrimSpace(sel.Lifetime),
		Handle:    strings.TrimSpace(sel.IdentityHandle),
	}
	if requireSigning {
		if client.SigningKey() == nil {
			return nil, usageError("current identity has no local signing key")
		}
		current.SigningKey = client.SigningKey()
	}

	if current.Handle != "" {
		current.Address = selectionAddress(sel)
	}
	if current.Address != "" {
		resolved, resolveErr := (&awid.ServerResolver{Client: client.Client}).Resolve(ctx, current.Address)
		if resolveErr == nil && resolved != nil {
			current.Identity = resolved
			if strings.TrimSpace(resolved.Address) != "" {
				current.Address = strings.TrimSpace(resolved.Address)
			}
			if strings.TrimSpace(resolved.Handle) != "" {
				current.Handle = strings.TrimSpace(resolved.Handle)
			}
			if strings.TrimSpace(resolved.DID) != "" {
				current.DID = strings.TrimSpace(resolved.DID)
			}
			if strings.TrimSpace(resolved.StableID) != "" {
				current.StableID = strings.TrimSpace(resolved.StableID)
			}
			if strings.TrimSpace(resolved.Custody) != "" {
				current.Custody = strings.TrimSpace(resolved.Custody)
			}
			if strings.TrimSpace(resolved.Lifetime) != "" {
				current.Lifetime = strings.TrimSpace(resolved.Lifetime)
			}
		}
	}
	if current.Address != "" {
		if domain, handle, ok := cutIdentityAddress(current.Address); ok {
			current.Domain = domain
			if current.Handle == "" {
				current.Handle = handle
			}
		}
	}
	if current.Handle == "" {
		current.Handle = strings.TrimSpace(sel.IdentityHandle)
	}
	if current.Domain == "" && strings.Contains(strings.TrimSpace(sel.NamespaceSlug), ".") {
		current.Domain = strings.TrimSpace(sel.NamespaceSlug)
	}
	return current, nil
}

func requirePermanentSelfCustodial(current *currentIdentityContext) error {
	if current == nil {
		return fmt.Errorf("missing identity context")
	}
	if strings.TrimSpace(current.Lifetime) != awid.LifetimePersistent {
		return usageError("this command requires a permanent identity")
	}
	if strings.TrimSpace(current.Custody) != awid.CustodySelf {
		return usageError("this command requires a self-custodial identity")
	}
	if strings.TrimSpace(current.StableID) == "" {
		return fmt.Errorf("current identity is missing a did:aw stable identifier")
	}
	if strings.TrimSpace(current.DID) == "" {
		return fmt.Errorf("current identity is missing a did:key")
	}
	if current.SigningKey == nil {
		return usageError("current identity has no local signing key")
	}
	return nil
}

func (c *currentIdentityContext) registryURL(ctx context.Context) (string, error) {
	if c == nil {
		return "", fmt.Errorf("missing identity context")
	}
	if strings.TrimSpace(c.Domain) != "" {
		return c.Registry.DiscoverRegistry(ctx, c.Domain)
	}
	return c.Registry.DefaultRegistryURL, nil
}

func registryLookupURL(ctx context.Context, registry *awid.RegistryClient, sel *awconfig.Selection, didAW string) (string, error) {
	if registry == nil {
		return "", fmt.Errorf("missing registry client")
	}
	if sel != nil && strings.TrimSpace(sel.StableID) == strings.TrimSpace(didAW) {
		address := selectionAddress(sel)
		if domain, _, ok := cutIdentityAddress(address); ok && strings.TrimSpace(domain) != "" {
			return registry.DiscoverRegistry(ctx, domain)
		}
	}
	return registry.DefaultRegistryURL, nil
}

func resolveRegistryClientForLookup() (*awid.RegistryClient, *awconfig.Selection, error) {
	wd, _ := os.Getwd()
	sel, err := resolveSelectionForDir(wd)
	if err == nil {
		baseURL, baseErr := resolveAuthenticatedBaseURL(sel.BaseURL)
		if baseErr != nil {
			return nil, nil, baseErr
		}
		sel.BaseURL = baseURL
		registry, regErr := newConfiguredRegistryClient(nil, baseURL)
		return registry, sel, regErr
	}
	registry, regErr := newConfiguredRegistryClient(nil, strings.TrimSpace(os.Getenv("AWEB_URL")))
	return registry, nil, regErr
}

func registryStatusCode(err error) (int, bool) {
	var regErr *awid.RegistryError
	if !errors.As(err, &regErr) {
		return 0, false
	}
	return regErr.StatusCode, true
}

func cutIdentityAddress(address string) (string, string, bool) {
	domain, handle, ok := strings.Cut(strings.TrimSpace(address), "/")
	if !ok || strings.TrimSpace(domain) == "" || strings.TrimSpace(handle) == "" {
		return "", "", false
	}
	return strings.TrimSpace(domain), strings.TrimSpace(handle), true
}
