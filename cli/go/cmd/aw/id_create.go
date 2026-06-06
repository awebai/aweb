package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idCreateOutput struct {
	Status            string `json:"status"`
	Address           string `json:"address"`
	DIDAW             string `json:"did_aw"`
	DIDKey            string `json:"did_key"`
	ControllerDID     string `json:"controller_did"`
	IdentityPath      string `json:"identity_path"`
	SigningKeyPath    string `json:"signing_key_path"`
	EncryptionKeyID   string `json:"encryption_key_id,omitempty"`
	EncryptionKeyPath string `json:"encryption_key_path,omitempty"`
	RegistryStatus    string `json:"registry_status"`
	RegistryURL       string `json:"registry_url,omitempty"`
	RegistryError     string `json:"registry_error,omitempty"`
}

var (
	idCreateName          string
	idCreateDomain        string
	idCreateRegistryURL   string
	idCreateSkipDNSVerify bool
	idCreateCmd           = &cobra.Command{
		Use:   "create",
		Short: "Create a standalone global identity with a DNS-backed address in .aw/",
		RunE:  runIDCreate,
	}
)

func init() {
	idCreateCmd.Flags().StringVar(&idCreateName, "name", "", "Global identity name")
	idCreateCmd.Flags().StringVar(&idCreateDomain, "domain", "", "Global identity domain")
	idCreateCmd.Flags().StringVar(&idCreateRegistryURL, "registry", "", "Registry origin override (default: api.awid.ai)")
	idCreateCmd.Flags().BoolVar(&idCreateSkipDNSVerify, "skip-dns-verify", false, "Skip the DNS TXT verification prompt and lookup")
	identityCmd.AddCommand(idCreateCmd)
}

type idCreateOptions struct {
	Name                     string
	Domain                   string
	RegistryURL              string
	AllowReservedLocalDomain bool
	SkipDNSVerify            bool
	PromptIn                 io.Reader
	PromptOut                io.Writer
	TXTResolver              awid.TXTResolver
	Now                      func() time.Time
}

type idCreatePlan struct {
	Name           string
	Domain         string
	Address        string
	DIDAW          string
	DIDKey         string
	ControllerDID  string
	RegistryURL    string
	DNSRecordName  string
	DNSRecordValue string
	IdentityPath   string
	SigningKeyPath string
	CreatedAt      string
	NeedsDNSSetup  bool
}

type preparedIDCreate struct {
	Plan          *idCreatePlan
	IdentityKey   ed25519.PrivateKey
	ControllerKey ed25519.PrivateKey
}

func runIDCreate(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(idCreateName) == "" {
		return usageError("--name is required")
	}
	if strings.TrimSpace(idCreateDomain) == "" {
		return usageError("--domain is required")
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	out, err := executeIDCreate(workingDir, idCreateOptions{
		Name:          idCreateName,
		Domain:        idCreateDomain,
		RegistryURL:   idCreateRegistryURL,
		SkipDNSVerify: idCreateSkipDNSVerify,
		PromptIn:      cmd.InOrStdin(),
		PromptOut:     cmd.ErrOrStderr(),
		Now:           time.Now,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDCreate)
	return nil
}

func executeIDCreate(workingDir string, opts idCreateOptions) (idCreateOutput, error) {
	prepared, err := prepareIDCreatePlan(workingDir, opts)
	if err != nil {
		return idCreateOutput{}, err
	}
	plan := prepared.Plan

	if err := printIDCreateDNSInstructions(plan, opts.PromptOut); err != nil {
		return idCreateOutput{}, err
	}

	if err := confirmAndVerifyIDCreateDNS(plan, opts); err != nil {
		return idCreateOutput{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return idCreateOutput{}, err
	}
	if err := registry.SetFallbackRegistryURL(plan.RegistryURL); err != nil {
		return idCreateOutput{}, fmt.Errorf("invalid planned registry URL: %w", err)
	}

	registryStatus := "registered"
	registryErr := ""
	if err := ensureStandaloneRegistryRegistration(ctx, registry, plan, prepared.ControllerKey, prepared.IdentityKey); err != nil {
		return idCreateOutput{}, idCreateAtomicClaimError(plan, err)
	}

	if err := awconfig.SaveWorktreeIdentityTo(plan.IdentityPath, &awconfig.WorktreeIdentity{
		DID:            plan.DIDKey,
		StableID:       plan.DIDAW,
		Address:        plan.Address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    plan.RegistryURL,
		RegistryStatus: registryStatus,
		CreatedAt:      plan.CreatedAt,
	}); err != nil {
		return idCreateOutput{}, err
	}
	if err := awid.SaveSigningKey(plan.SigningKeyPath, prepared.IdentityKey); err != nil {
		return idCreateOutput{}, err
	}

	encryptionKeyID := ""
	encryptionKeyPath := ""
	identity := &awconfig.ResolvedIdentity{
		WorkingDir:     workingDir,
		IdentityPath:   plan.IdentityPath,
		SigningKeyPath: plan.SigningKeyPath,
		DID:            plan.DIDKey,
		StableID:       plan.DIDAW,
		Address:        plan.Address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    plan.RegistryURL,
		RegistryStatus: registryStatus,
		CreatedAt:      plan.CreatedAt,
	}
	record, assertion, err := createLocalEncryptionKeyRecord(identity, prepared.IdentityKey, "")
	if err != nil {
		return idCreateOutput{}, err
	}
	state := &awconfig.EncryptionKeyState{ActiveKeyID: record.KeyID}
	state.UpsertRecord(*record)
	if err := awconfig.SaveEncryptionKeyStateTo(awconfig.WorktreeEncryptionStatePath(workingDir), state); err != nil {
		return idCreateOutput{}, err
	}
	if registryStatus == "registered" {
		if err := registry.PublishEncryptionKey(ctx, plan.RegistryURL, plan.DIDAW, assertion); err != nil {
			registryErr = strings.TrimSpace(firstNonEmpty(registryErr, fmt.Sprintf("encryption key publish pending: %v", err)))
		} else {
			record.PublishedAt = time.Now().UTC().Format(time.RFC3339)
			state.UpsertRecord(*record)
			_ = awconfig.SaveEncryptionKeyStateTo(awconfig.WorktreeEncryptionStatePath(workingDir), state)
		}
	}
	encryptionKeyID = record.KeyID
	encryptionKeyPath = resolveWorktreeRelativePath(workingDir, record.PrivateKeyPath)

	return idCreateOutput{
		Status:            "created",
		Address:           plan.Address,
		DIDAW:             plan.DIDAW,
		DIDKey:            plan.DIDKey,
		ControllerDID:     plan.ControllerDID,
		IdentityPath:      plan.IdentityPath,
		SigningKeyPath:    plan.SigningKeyPath,
		EncryptionKeyID:   encryptionKeyID,
		EncryptionKeyPath: encryptionKeyPath,
		RegistryStatus:    registryStatus,
		RegistryURL:       plan.RegistryURL,
		RegistryError:     registryErr,
	}, nil
}

func prepareIDCreatePlan(workingDir string, opts idCreateOptions) (*preparedIDCreate, error) {
	name, err := normalizeIDCreateName(opts.Name)
	if err != nil {
		return nil, err
	}
	domain, err := normalizeIDCreateDomain(opts.Domain, opts.AllowReservedLocalDomain)
	if err != nil {
		return nil, err
	}

	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	workspacePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := ensureStandaloneIdentityTarget(identityPath, signingKeyPath, workspacePath); err != nil {
		return nil, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.RegistryURL) != "" {
		if err := registry.SetFallbackRegistryURL(opts.RegistryURL); err != nil {
			return nil, fmt.Errorf("invalid --registry: %w", err)
		}
	}
	registryURL := strings.TrimSpace(registry.DefaultRegistryURL)
	if strings.TrimSpace(opts.RegistryURL) == "" {
		discoveredRegistryURL, err := discoverIDCreateRegistryURL(domain, opts.TXTResolver)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(discoveredRegistryURL) != "" {
			registryURL = strings.TrimSpace(discoveredRegistryURL)
		}
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	controllerKey, controllerDID, createdController, err := resolveOrCreateControllerKey(domain, registryURL, now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}

	pub, identityKey, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	didKey := awid.ComputeDIDKey(pub)
	plan := &idCreatePlan{
		Name:           name,
		Domain:         domain,
		Address:        domain + "/" + name,
		DIDAW:          awid.ComputeStableID(pub),
		DIDKey:         didKey,
		ControllerDID:  controllerDID,
		RegistryURL:    registryURL,
		DNSRecordName:  awid.AWIDTXTName(domain),
		DNSRecordValue: idCreateDNSRecordValue(controllerDID, registryURL),
		IdentityPath:   identityPath,
		SigningKeyPath: signingKeyPath,
		CreatedAt:      now().UTC().Format(time.RFC3339),
		NeedsDNSSetup:  createdController,
	}
	return &preparedIDCreate{
		Plan:          plan,
		IdentityKey:   identityKey,
		ControllerKey: controllerKey,
	}, nil
}

func discoverIDCreateRegistryURL(domain string, resolver awid.TXTResolver) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authority, err := awid.VerifyExactDomainAuthority(ctx, resolver, domain)
	if err != nil {
		if isIDCreateTXTLookupMiss(err) {
			return "", nil
		}
		return "", err
	}
	registryURL := strings.TrimSpace(authority.RegistryURL)
	if registryURL == "" {
		return awid.DefaultAWIDRegistryURL, nil
	}
	return registryURL, nil
}

func isIDCreateTXTLookupMiss(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no awid txt record found") || strings.Contains(msg, "no txt records found")
}

func confirmAndVerifyIDCreateDNS(plan *idCreatePlan, opts idCreateOptions) error {
	if !plan.NeedsDNSSetup {
		return nil
	}
	if opts.SkipDNSVerify {
		return nil
	}
	promptIn := opts.PromptIn
	if promptIn == nil {
		promptIn = os.Stdin
	}
	promptOut := opts.PromptOut
	if promptOut == nil {
		promptOut = os.Stderr
	}
	if readerIsNonTerminalFile(promptIn) {
		return idCreateDNSNeedsInteractiveInputError(plan)
	}
	for {
		proceed, err := promptYesNoWithIO("Verify this DNS TXT record now?", true, promptIn, promptOut)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return idCreateDNSNeedsInteractiveInputError(plan)
			}
			return err
		}
		if !proceed {
			return usageError("DNS verification cancelled; rerun after publishing the TXT record or pass --skip-dns-verify")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = verifyIDCreateDomainAuthority(ctx, opts.TXTResolver, plan.Domain, plan.ControllerDID, plan.RegistryURL)
		cancel()
		if err == nil {
			return nil
		}
		fmt.Fprintf(promptOut, "%v\n", err)
	}
}

func idCreateDNSNeedsInteractiveInputError(plan *idCreatePlan) error {
	return usageError("DNS verification needs interactive input. Publish the TXT record, verify it with `aw id namespace check-txt --domain %s`, then rerun `aw id create --domain %s --name %s`.", plan.Domain, plan.Domain, plan.Name)
}

func verifyIDCreateDomainAuthority(ctx context.Context, resolver awid.TXTResolver, domain, expectedControllerDID, expectedRegistryURL string) error {
	authority, err := awid.VerifyExactDomainAuthority(ctx, resolver, domain)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	if strings.TrimSpace(authority.ControllerDID) != strings.TrimSpace(expectedControllerDID) {
		return fmt.Errorf("TXT controller %s does not match %s", authority.ControllerDID, expectedControllerDID)
	}
	if strings.TrimSpace(authority.RegistryURL) != strings.TrimSpace(expectedRegistryURL) {
		return fmt.Errorf("TXT registry %s does not match %s", authority.RegistryURL, expectedRegistryURL)
	}
	return nil
}

func printIDCreateDNSInstructions(plan *idCreatePlan, out io.Writer) error {
	if out == nil || !plan.NeedsDNSSetup {
		return nil
	}
	_, err := fmt.Fprintf(out,
		"Create this DNS TXT record before continuing:\n  Name:  %s\n  Value: %s\n",
		plan.DNSRecordName,
		plan.DNSRecordValue,
	)
	return err
}

func idCreateDNSRecordValue(controllerDID, registryURL string) string {
	registryURL = strings.TrimSpace(registryURL)
	if registryURL != "" && registryURL != awid.DefaultAWIDRegistryURL {
		return fmt.Sprintf("awid=v1; controller=%s; registry=%s;", controllerDID, registryURL)
	}
	return fmt.Sprintf("awid=v1; controller=%s;", controllerDID)
}

func ensureStandaloneRegistryRegistration(
	ctx context.Context,
	registry *awid.RegistryClient,
	plan *idCreatePlan,
	controllerKey ed25519.PrivateKey,
	identityKey ed25519.PrivateKey,
) error {
	if err := ensureStandaloneNamespace(ctx, registry, plan, controllerKey); err != nil {
		return err
	}
	_, err := registry.ClaimIdentityAddressAt(ctx, plan.RegistryURL, awid.AtomicAddressClaimParams{
		Domain:                        plan.Domain,
		AddressName:                   plan.Name,
		DIDAW:                         plan.DIDAW,
		CurrentDIDKey:                 plan.DIDKey,
		IdentitySigningKey:            identityKey,
		NamespaceControllerSigningKey: controllerKey,
		IdentityCustody:               string(awid.AddressClaimCustodySelf),
		NamespaceCustody:              string(awid.AddressClaimCustodySelf),
	})
	if err != nil {
		return err
	}
	return nil
}

func ensureStandaloneNamespace(
	ctx context.Context,
	registry *awid.RegistryClient,
	plan *idCreatePlan,
	controllerKey ed25519.PrivateKey,
) error {
	namespace, _, err := registry.GetNamespaceAt(ctx, plan.RegistryURL, plan.Domain)
	if err == nil {
		if strings.TrimSpace(namespace.ControllerDID) != plan.ControllerDID {
			return fmt.Errorf("namespace %s is already controlled by %s", plan.Domain, namespace.ControllerDID)
		}
		return nil
	}
	if code, ok := registryStatusCode(err); !ok || code != http.StatusNotFound {
		return err
	}
	namespace, err = registry.RegisterNamespaceAt(ctx, plan.RegistryURL, plan.Domain, plan.ControllerDID, controllerKey)
	if err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusConflict {
			namespace, _, err = registry.GetNamespaceAt(ctx, plan.RegistryURL, plan.Domain)
			if err != nil {
				return err
			}
			if strings.TrimSpace(namespace.ControllerDID) != plan.ControllerDID {
				return fmt.Errorf("namespace %s is already controlled by %s", plan.Domain, namespace.ControllerDID)
			}
			return nil
		}
		return err
	}
	if strings.TrimSpace(namespace.ControllerDID) != plan.ControllerDID {
		return fmt.Errorf("namespace %s registered unexpected controller %s", plan.Domain, namespace.ControllerDID)
	}
	return nil
}

func idCreateAtomicClaimError(plan *idCreatePlan, err error) error {
	if plan == nil || err == nil {
		return err
	}
	var conflict *awid.AtomicAddressClaimConflictError
	if errors.As(err, &conflict) {
		switch conflict.Code {
		case awid.AtomicAddressClaimCodeAddressTakenDifferentOwner:
			return usageError("address %s is already claimed by another identity; choose a different --name or inspect the namespace address before retrying", plan.Address)
		case awid.AtomicAddressClaimCodeDIDTakenDifferentKey:
			return usageError("did:aw %s already exists with a different key; use a clean directory or restore the original .aw/signing.key before retrying", plan.DIDAW)
		case awid.AtomicAddressClaimCodeNamespaceAuthorityInvalid:
			return usageError("namespace authority for %s is invalid; run `aw id namespace check-txt --domain %s`, then restore the matching ~/.awid controller key before retrying", plan.Domain, plan.Domain)
		case awid.AtomicAddressClaimCodeNamespaceNotRegistered:
			return usageError("namespace %s is not registered at AWID; run `aw id namespace prepare-controller --domain %s`, publish and verify _awid with `aw id namespace check-txt --domain %s`, then retry", plan.Domain, plan.Domain, plan.Domain)
		case awid.AtomicAddressClaimCodePrimitiveDisabled, awid.AtomicAddressClaimCodePrimitiveNotSupported:
			return usageError("AWID server at %s does not support atomic identity/address claims; upgrade awid-service before running `aw id create`", plan.RegistryURL)
		case awid.AtomicAddressClaimCodeIdentitySignatureInvalid,
			awid.AtomicAddressClaimCodeTimestampStale,
			awid.AtomicAddressClaimCodePayloadCanonicalization,
			awid.AtomicAddressClaimCodeCustodyCombinationUnsupported,
			awid.AtomicAddressClaimCodeDIDLogProofRequired,
			awid.AtomicAddressClaimCodeDIDLogProofInvalid:
			return usageError("atomic identity/address claim for %s failed with %s: %s", plan.Address, conflict.Code, strings.TrimSpace(conflict.Message))
		default:
			return usageError("atomic identity/address claim for %s failed with %s: %s", plan.Address, conflict.Code, strings.TrimSpace(conflict.Message))
		}
	}
	if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
		return usageError("AWID server at %s does not support atomic identity/address claims; upgrade awid-service before running `aw id create`", plan.RegistryURL)
	}
	if isRegistryUnavailableError(err) {
		return usageError("could not reach AWID registry at %s for atomic identity/address claim; no local .aw identity was written: %v", plan.RegistryURL, err)
	}
	return err
}

func resolveOrCreateControllerKey(domain, registryURL, createdAt string) (ed25519.PrivateKey, string, bool, error) {
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, "", false, err
	}
	if exists {
		key, err := awconfig.LoadControllerKey(domain)
		if err != nil {
			return nil, "", false, err
		}
		controllerDID := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		if _, err := awconfig.LoadControllerMeta(domain); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, "", false, err
			}
			if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
				Domain:        domain,
				ControllerDID: controllerDID,
				RegistryURL:   registryURL,
				CreatedAt:     createdAt,
			}); err != nil {
				return nil, "", false, err
			}
		}
		return key, controllerDID, false, nil
	}

	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		return nil, "", false, err
	}
	controllerDID := awid.ComputeDIDKey(pub)
	if err := awconfig.SaveControllerKey(domain, key); err != nil {
		return nil, "", false, err
	}
	if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
		Domain:        domain,
		ControllerDID: controllerDID,
		RegistryURL:   registryURL,
		CreatedAt:     createdAt,
	}); err != nil {
		// Clean up the key file so the next retry starts fresh
		keyPath, _ := awconfig.ControllerKeyPath(domain)
		if keyPath != "" {
			_ = os.Remove(keyPath)
		}
		return nil, "", false, err
	}
	return key, controllerDID, true, nil
}

func ensureStandaloneIdentityTarget(identityPath, signingKeyPath, workspacePath string) error {
	if _, err := os.Stat(identityPath); err == nil {
		return usageError("standalone identity already exists at %s", identityPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(workspacePath); err == nil {
		return usageError("current directory already has a workspace at %s; use a clean directory for `aw id create`", workspacePath)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(signingKeyPath); err == nil {
		return usageError("refusing to overwrite existing signing key at %s", signingKeyPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func normalizeIDCreateName(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "":
		return "", usageError("--name is required")
	case strings.Contains(value, "/"):
		return "", usageError("--name must not contain '/'")
	}
	return value, nil
}

func normalizeIDCreateDomain(value string, allowReservedLocal bool) (string, error) {
	value = awconfig.NormalizeDomain(value)
	switch {
	case value == "":
		return "", usageError("--domain is required")
	case strings.Contains(value, "/"):
		return "", usageError("--domain must not contain '/'")
	case value == implicitLocalDomain && allowReservedLocal:
		return value, nil
	case !strings.Contains(value, "."):
		return "", usageError("--domain must be a fully qualified domain name")
	}
	return value, nil
}

func isRegistryUnavailableError(err error) bool {
	var regErr *awid.RegistryError
	if errors.As(err, &regErr) {
		return regErr.StatusCode >= 500
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}
