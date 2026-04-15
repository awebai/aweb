package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
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
	Use:   "namespace [domain]",
	Short: "Inspect or recover namespace controller state",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runIDNamespace,
}

var (
	idNamespaceRotateControllerDomain string
	idNamespaceRotateControllerCmd    = &cobra.Command{
		Use:   "rotate-controller",
		Short: "Recover namespace control by rotating to a new controller key",
		RunE:  runIDNamespaceRotateController,
	}
)

func init() {
	identityCmd.AddCommand(idRegisterCmd)
	identityCmd.AddCommand(idShowCmd)
	identityCmd.AddCommand(idResolveCmd)
	identityCmd.AddCommand(idVerifyCmd)
	idNamespaceRotateControllerCmd.Flags().StringVar(&idNamespaceRotateControllerDomain, "domain", "", "Namespace domain to rotate")
	idNamespaceCmd.AddCommand(idNamespaceRotateControllerCmd)
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
	registryURL, err := currentIdentityRegistryURL(ctx, identity, registry)
	if err != nil {
		return err
	}
	mapping, err := registry.RegisterDID(
		ctx,
		registryURL,
		"",
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
			Server:        "",
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

	workingDir, _ := os.Getwd()
	registry, identity, err := resolveRegistryClientForLookup(workingDir)
	if err != nil {
		return err
	}
	didAW := strings.TrimSpace(args[0])
	if !strings.HasPrefix(didAW, "did:aw:") {
		return usageError("did_aw must start with did:aw:")
	}
	registryURL, err := registryLookupURL(ctx, registry, identity, didAW)
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

	workingDir, _ := os.Getwd()
	registry, identity, err := resolveRegistryClientForLookup(workingDir)
	if err != nil {
		return err
	}
	didAW := strings.TrimSpace(args[0])
	if !strings.HasPrefix(didAW, "did:aw:") {
		return usageError("did_aw must start with did:aw:")
	}
	registryURL, err := registryLookupURL(ctx, registry, identity, didAW)
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
	if len(args) != 1 {
		return usageError("domain is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workingDir, _ := os.Getwd()
	registry, _, err := resolveRegistryClientForLookup(workingDir)
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
	lookupSigningKey, err := loadOptionalWorktreeSigningKey(workingDir)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}
	var addresses []awid.RegistryAddress
	if lookupSigningKey != nil {
		addresses, _, err = registry.ListNamespaceAddressesAtSigned(ctx, registryURL, domain, lookupSigningKey)
	} else {
		addresses, _, err = registry.ListNamespaceAddressesAt(ctx, registryURL, domain)
	}
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

type idNamespaceRotateControllerOptions struct {
	Domain      string
	PromptIn    io.Reader
	PromptOut   io.Writer
	TXTResolver awid.TXTResolver
	Now         func() time.Time
}

func runIDNamespaceRotateController(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(idNamespaceRotateControllerDomain) == "" {
		return usageError("--domain is required")
	}
	out, err := executeIDNamespaceRotateController(idNamespaceRotateControllerOptions{
		Domain:      idNamespaceRotateControllerDomain,
		PromptIn:    cmd.InOrStdin(),
		PromptOut:   cmd.ErrOrStderr(),
		TXTResolver: nil,
		Now:         time.Now,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDRotate)
	return nil
}

func executeIDNamespaceRotateController(opts idNamespaceRotateControllerOptions) (idRotateOutput, error) {
	domain := awconfig.NormalizeDomain(opts.Domain)
	if domain == "" {
		return idRotateOutput{}, usageError("--domain is required")
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registry, err := resolveNamespaceRegistryClient(domain)
	if err != nil {
		return idRotateOutput{}, err
	}
	registryURL, err := currentNamespaceRegistryURL(ctx, registry, domain)
	if err != nil {
		return idRotateOutput{}, err
	}
	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return idRotateOutput{}, err
	}
	oldControllerDID := strings.TrimSpace(namespace.ControllerDID)
	if oldControllerDID == "" {
		return idRotateOutput{}, fmt.Errorf("namespace %s is missing controller_did", domain)
	}

	controllerKey, newControllerDID, createdAt, err := resolveOrStageNamespaceRecoveryControllerKey(
		domain,
		oldControllerDID,
		registryURL,
		now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return idRotateOutput{}, err
	}

	plan := &idCreatePlan{
		Domain:         domain,
		ControllerDID:  newControllerDID,
		RegistryURL:    registryURL,
		DNSRecordName:  awid.AWIDTXTName(domain),
		DNSRecordValue: idCreateDNSRecordValue(newControllerDID, registryURL),
		NeedsDNSSetup:  domain != implicitLocalDomain,
	}
	if err := printIDCreateDNSInstructions(plan, opts.PromptOut); err != nil {
		return idRotateOutput{}, err
	}
	if err := confirmAndVerifyIDCreateDNS(plan, idCreateOptions{
		PromptIn:    opts.PromptIn,
		PromptOut:   opts.PromptOut,
		TXTResolver: opts.TXTResolver,
	}); err != nil {
		return idRotateOutput{}, err
	}

	rotated, err := registry.RotateNamespaceControllerAt(ctx, registryURL, domain, newControllerDID, controllerKey)
	if err != nil {
		return idRotateOutput{}, err
	}
	if strings.TrimSpace(rotated.ControllerDID) != newControllerDID {
		return idRotateOutput{}, fmt.Errorf("namespace %s rotated unexpected controller %s", domain, rotated.ControllerDID)
	}

	if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
		Domain:        domain,
		ControllerDID: newControllerDID,
		RegistryURL:   registryURL,
		CreatedAt:     createdAt,
	}); err != nil {
		return idRotateOutput{}, err
	}

	return idRotateOutput{
		Status:      "rotated",
		RegistryURL: registryURL,
		OldDID:      oldControllerDID,
		NewDID:      newControllerDID,
	}, nil
}

func resolveNamespaceRegistryClient(domain string) (*awid.RegistryClient, error) {
	baseURL := ""
	meta, err := loadOptionalControllerMeta(domain)
	if err != nil {
		return nil, err
	}
	if meta != nil {
		baseURL = strings.TrimSpace(meta.RegistryURL)
	}
	return newRegistryClientWithPreferredBaseURL(baseURL)
}

func currentNamespaceRegistryURL(ctx context.Context, registry *awid.RegistryClient, domain string) (string, error) {
	if registry == nil {
		return "", fmt.Errorf("missing registry client")
	}
	if strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")) != "" {
		return strings.TrimSpace(registry.DefaultRegistryURL), nil
	}
	meta, err := loadOptionalControllerMeta(domain)
	if err != nil {
		return "", err
	}
	if meta != nil && strings.TrimSpace(meta.RegistryURL) != "" {
		return strings.TrimSpace(meta.RegistryURL), nil
	}
	return registry.DiscoverRegistry(ctx, domain)
}

func loadOptionalControllerMeta(domain string) (*awconfig.ControllerMeta, error) {
	meta, err := awconfig.LoadControllerMeta(domain)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return meta, nil
}

func resolveOrStageNamespaceRecoveryControllerKey(
	domain string,
	currentControllerDID string,
	registryURL string,
	createdAt string,
) (ed25519.PrivateKey, string, string, error) {
	var previousKey ed25519.PrivateKey
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, "", "", err
	}
	if exists {
		key, err := awconfig.LoadControllerKey(domain)
		if err != nil {
			return nil, "", "", err
		}
		did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		meta, err := loadOptionalControllerMeta(domain)
		if err != nil {
			return nil, "", "", err
		}
		metaCreatedAt := createdAt
		if meta != nil && strings.TrimSpace(meta.CreatedAt) != "" {
			metaCreatedAt = strings.TrimSpace(meta.CreatedAt)
		}
		if did != strings.TrimSpace(currentControllerDID) {
			if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
				Domain:        domain,
				ControllerDID: did,
				RegistryURL:   registryURL,
				CreatedAt:     metaCreatedAt,
			}); err != nil {
				return nil, "", "", err
			}
			return key, did, metaCreatedAt, nil
		}
		previousKey = key
	}

	// Stage the recovery key locally before DNS verification so reruns reuse the
	// same TXT record while propagation catches up.
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		return nil, "", "", err
	}
	did := awid.ComputeDIDKey(pub)
	if err := awconfig.SaveControllerKey(domain, key); err != nil {
		return nil, "", "", err
	}
	if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
		Domain:        domain,
		ControllerDID: did,
		RegistryURL:   registryURL,
		CreatedAt:     createdAt,
	}); err != nil {
		if previousKey != nil {
			_ = awconfig.SaveControllerKey(domain, previousKey)
		} else {
			keyPath, _ := awconfig.ControllerKeyPath(domain)
			if keyPath != "" {
				_ = os.Remove(keyPath)
			}
		}
		return nil, "", "", err
	}
	return key, did, createdAt, nil
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
	if strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")) != "" {
		return registry.DefaultRegistryURL, nil
	}
	if strings.TrimSpace(identity.RegistryURL) != "" {
		return strings.TrimSpace(identity.RegistryURL), nil
	}
	if strings.TrimSpace(identity.Domain) != "" {
		return registry.DiscoverRegistry(ctx, identity.Domain)
	}
	return registry.DefaultRegistryURL, nil
}

func registryLookupURL(ctx context.Context, registry *awid.RegistryClient, identity *awconfig.ResolvedIdentity, didAW string) (string, error) {
	if registry == nil {
		return "", fmt.Errorf("missing registry client")
	}
	if strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")) != "" {
		return registry.DefaultRegistryURL, nil
	}
	if identity != nil && strings.TrimSpace(identity.StableID) == strings.TrimSpace(didAW) {
		if strings.TrimSpace(identity.RegistryURL) != "" {
			return strings.TrimSpace(identity.RegistryURL), nil
		}
		if strings.TrimSpace(identity.Domain) != "" {
			return registry.DiscoverRegistry(ctx, identity.Domain)
		}
	}
	return registry.DefaultRegistryURL, nil
}

func resolveRegistryClientForLookup(workingDir string) (*awid.RegistryClient, *awconfig.ResolvedIdentity, error) {
	identity, err := resolveOptionalPersistentIdentityForLookup(workingDir)
	if err != nil {
		return nil, nil, err
	}
	baseURL := ""
	if identity != nil {
		baseURL = strings.TrimSpace(identity.RegistryURL)
	}
	registry, err := newRegistryClientWithPreferredBaseURL(baseURL)
	if err != nil {
		return nil, nil, err
	}
	return registry, identity, nil
}

func resolveIdentityRegistryClient(identity *awconfig.ResolvedIdentity) (*awid.RegistryClient, error) {
	baseURL := ""
	if identity != nil {
		baseURL = strings.TrimSpace(identity.RegistryURL)
	}
	registry, err := newRegistryClientWithPreferredBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return registry, nil
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

func resolveOptionalPersistentIdentityForLookup(workingDir string) (*awconfig.ResolvedIdentity, error) {
	identity, err := awconfig.ResolveIdentity(workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if err := validateRegistryLookupIdentity(identity); err != nil {
		return nil, err
	}
	return identity, nil
}

func newRegistryClientWithPreferredBaseURL(baseURL string) (*awid.RegistryClient, error) {
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")) != "" || strings.TrimSpace(baseURL) == "" {
		return registry, nil
	}
	if err := registry.SetFallbackRegistryURL(baseURL); err != nil {
		return nil, fmt.Errorf("invalid identity registry URL: %w", err)
	}
	return registry, nil
}

func validateRegistryLookupIdentity(identity *awconfig.ResolvedIdentity) error {
	if identity == nil {
		return fmt.Errorf("missing identity context")
	}
	if strings.TrimSpace(identity.DID) == "" {
		return usageError("current identity is invalid: .aw/identity.yaml is missing did")
	}
	return nil
}

func registryStatusCode(err error) (int, bool) {
	var regErr *awid.RegistryError
	if !errors.As(err, &regErr) {
		return 0, false
	}
	return regErr.StatusCode, true
}
