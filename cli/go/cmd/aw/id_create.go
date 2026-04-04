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
	Status         string `json:"status"`
	Address        string `json:"address"`
	DIDAW          string `json:"did_aw"`
	DIDKey         string `json:"did_key"`
	IdentityPath   string `json:"identity_path"`
	SigningKeyPath string `json:"signing_key_path"`
	RegistryStatus string `json:"registry_status"`
	RegistryURL    string `json:"registry_url,omitempty"`
	RegistryError  string `json:"registry_error,omitempty"`
}

var (
	idCreateName          string
	idCreateDomain        string
	idCreateRegistryURL   string
	idCreateSkipDNSVerify bool
	idCreateCmd           = &cobra.Command{
		Use:   "create",
		Short: "Create a standalone permanent identity with a DNS-backed address in .aw/",
		RunE:  runIDCreate,
	}
)

func init() {
	idCreateCmd.Flags().StringVar(&idCreateName, "name", "", "Permanent identity name")
	idCreateCmd.Flags().StringVar(&idCreateDomain, "domain", "", "Permanent identity domain")
	idCreateCmd.Flags().StringVar(&idCreateRegistryURL, "registry", "", "Registry origin override (default: api.awid.ai)")
	idCreateCmd.Flags().BoolVar(&idCreateSkipDNSVerify, "skip-dns-verify", false, "Skip the DNS TXT verification prompt and lookup")
	identityCmd.AddCommand(idCreateCmd)
}

type idCreateOptions struct {
	Name          string
	Domain        string
	RegistryURL   string
	SkipDNSVerify bool
	PromptIn      io.Reader
	PromptOut     io.Writer
	TXTResolver   awid.TXTResolver
	Now           func() time.Time
}

type idCreatePlan struct {
	Name           string
	Domain         string
	Address        string
	DIDAW          string
	DIDKey         string
	RegistryURL    string
	DNSRecordName  string
	DNSRecordValue string
	IdentityPath   string
	SigningKeyPath string
	CreatedAt      string
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeIDCreate(ctx, workingDir, idCreateOptions{
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

func executeIDCreate(ctx context.Context, workingDir string, opts idCreateOptions) (idCreateOutput, error) {
	plan, signingKey, err := prepareIDCreatePlan(workingDir, opts)
	if err != nil {
		return idCreateOutput{}, err
	}

	if err := printIDCreateDNSInstructions(plan, opts.PromptOut); err != nil {
		return idCreateOutput{}, err
	}
	if err := confirmAndVerifyIDCreateDNS(ctx, plan, opts); err != nil {
		return idCreateOutput{}, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return idCreateOutput{}, err
	}

	registryStatus := "registered"
	registryErr := ""
	if err := ensureStandaloneRegistryRegistration(ctx, registry, plan, signingKey); err != nil {
		if !isRegistryUnavailableError(err) {
			return idCreateOutput{}, err
		}
		registryStatus = "pending"
		registryErr = err.Error()
		warnWriter := opts.PromptOut
		if warnWriter == nil {
			warnWriter = os.Stderr
		}
		fmt.Fprintf(warnWriter, "Warning: could not finish identity registration at %s: %v\n", plan.RegistryURL, err)
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
	if err := awid.SaveSigningKey(plan.SigningKeyPath, signingKey); err != nil {
		return idCreateOutput{}, err
	}

	return idCreateOutput{
		Status:         "created",
		Address:        plan.Address,
		DIDAW:          plan.DIDAW,
		DIDKey:         plan.DIDKey,
		IdentityPath:   plan.IdentityPath,
		SigningKeyPath: plan.SigningKeyPath,
		RegistryStatus: registryStatus,
		RegistryURL:    plan.RegistryURL,
		RegistryError:  registryErr,
	}, nil
}

func prepareIDCreatePlan(workingDir string, opts idCreateOptions) (*idCreatePlan, ed25519.PrivateKey, error) {
	name, err := normalizeIDCreateName(opts.Name)
	if err != nil {
		return nil, nil, err
	}
	domain, err := normalizeIDCreateDomain(opts.Domain)
	if err != nil {
		return nil, nil, err
	}

	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	workspacePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := ensureStandaloneIdentityTarget(identityPath, signingKeyPath, workspacePath); err != nil {
		return nil, nil, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(opts.RegistryURL) != "" {
		if err := registry.SetFallbackRegistryURL(opts.RegistryURL); err != nil {
			return nil, nil, fmt.Errorf("invalid --registry: %w", err)
		}
	}

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	didKey := awid.ComputeDIDKey(pub)
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	plan := &idCreatePlan{
		Name:           name,
		Domain:         domain,
		Address:        domain + "/" + name,
		DIDAW:          awid.ComputeStableID(pub),
		DIDKey:         didKey,
		RegistryURL:    strings.TrimSpace(registry.DefaultRegistryURL),
		DNSRecordName:  awid.AWIDTXTName(domain),
		DNSRecordValue: idCreateDNSRecordValue(didKey, strings.TrimSpace(registry.DefaultRegistryURL)),
		IdentityPath:   identityPath,
		SigningKeyPath: signingKeyPath,
		CreatedAt:      now().UTC().Format(time.RFC3339),
	}
	return plan, signingKey, nil
}

func confirmAndVerifyIDCreateDNS(ctx context.Context, plan *idCreatePlan, opts idCreateOptions) error {
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
	proceed, err := promptYesNoWithIO("Verify this DNS TXT record now?", true, promptIn, promptOut)
	if err != nil {
		return err
	}
	if !proceed {
		return usageError("DNS verification cancelled; rerun after publishing the TXT record or pass --skip-dns-verify")
	}
	return verifyIDCreateDomainAuthority(ctx, opts.TXTResolver, plan.Domain, plan.DIDKey, plan.RegistryURL)
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
	if out == nil {
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
	signingKey ed25519.PrivateKey,
) error {
	if err := ensureStandaloneNamespace(ctx, registry, plan, signingKey); err != nil {
		return err
	}
	if err := ensureStandaloneAddress(ctx, registry, plan, signingKey); err != nil {
		return err
	}
	return ensureStandaloneDID(ctx, registry, plan, signingKey)
}

func ensureStandaloneNamespace(
	ctx context.Context,
	registry *awid.RegistryClient,
	plan *idCreatePlan,
	signingKey ed25519.PrivateKey,
) error {
	namespace, _, err := registry.GetNamespaceAt(ctx, plan.RegistryURL, plan.Domain)
	if err == nil {
		if strings.TrimSpace(namespace.ControllerDID) != plan.DIDKey {
			return fmt.Errorf("namespace %s is already controlled by %s", plan.Domain, namespace.ControllerDID)
		}
		return nil
	}
	if code, ok := registryStatusCode(err); !ok || code != http.StatusNotFound {
		return err
	}
	namespace, err = registry.RegisterNamespaceAt(ctx, plan.RegistryURL, plan.Domain, plan.DIDKey, signingKey)
	if err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusConflict {
			namespace, _, err = registry.GetNamespaceAt(ctx, plan.RegistryURL, plan.Domain)
			if err != nil {
				return err
			}
			if strings.TrimSpace(namespace.ControllerDID) != plan.DIDKey {
				return fmt.Errorf("namespace %s is already controlled by %s", plan.Domain, namespace.ControllerDID)
			}
			return nil
		}
		return err
	}
	if strings.TrimSpace(namespace.ControllerDID) != plan.DIDKey {
		return fmt.Errorf("namespace %s registered unexpected controller %s", plan.Domain, namespace.ControllerDID)
	}
	return nil
}

func ensureStandaloneAddress(
	ctx context.Context,
	registry *awid.RegistryClient,
	plan *idCreatePlan,
	signingKey ed25519.PrivateKey,
) error {
	address, _, err := registry.GetNamespaceAddressAt(ctx, plan.RegistryURL, plan.Domain, plan.Name)
	if err == nil {
		if strings.TrimSpace(address.DIDAW) != plan.DIDAW {
			return fmt.Errorf("address %s is already assigned to %s", plan.Address, address.DIDAW)
		}
		if strings.TrimSpace(address.CurrentDIDKey) != plan.DIDKey {
			return fmt.Errorf("address %s is already pinned to %s", plan.Address, address.CurrentDIDKey)
		}
		return nil
	}
	if code, ok := registryStatusCode(err); !ok || code != http.StatusNotFound {
		return err
	}
	address, err = registry.RegisterAddressAt(ctx, plan.RegistryURL, plan.Domain, plan.Name, plan.DIDAW, plan.DIDKey, "public", signingKey)
	if err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusConflict {
			address, _, err = registry.GetNamespaceAddressAt(ctx, plan.RegistryURL, plan.Domain, plan.Name)
			if err != nil {
				return err
			}
			if strings.TrimSpace(address.DIDAW) != plan.DIDAW {
				return fmt.Errorf("address %s is already assigned to %s", plan.Address, address.DIDAW)
			}
			if strings.TrimSpace(address.CurrentDIDKey) != plan.DIDKey {
				return fmt.Errorf("address %s is already pinned to %s", plan.Address, address.CurrentDIDKey)
			}
			return nil
		}
		return err
	}
	if strings.TrimSpace(address.DIDAW) != plan.DIDAW {
		return fmt.Errorf("address %s registered unexpected did:aw %s", plan.Address, address.DIDAW)
	}
	return nil
}

func ensureStandaloneDID(
	ctx context.Context,
	registry *awid.RegistryClient,
	plan *idCreatePlan,
	signingKey ed25519.PrivateKey,
) error {
	mapping, err := registry.RegisterDID(ctx, plan.RegistryURL, "", plan.Address, plan.Name, plan.DIDKey, plan.DIDAW, signingKey)
	if already := new(awid.AlreadyRegisteredError); errors.As(err, &already) {
		if strings.TrimSpace(already.ExistingDIDKey) != plan.DIDKey {
			return fmt.Errorf("did:aw %s is already registered to %s", already.DIDAW, already.ExistingDIDKey)
		}
		mapping, err = registry.GetDIDFull(ctx, plan.RegistryURL, plan.DIDAW, signingKey)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if strings.TrimSpace(mapping.Server) != "" {
		return fmt.Errorf("did:aw %s is already bound to server %s", plan.DIDAW, mapping.Server)
	}
	if strings.TrimSpace(mapping.Address) != plan.Address {
		return fmt.Errorf("did:aw %s is already bound to address %s", plan.DIDAW, mapping.Address)
	}
	handle := ""
	if mapping.Handle != nil {
		handle = strings.TrimSpace(*mapping.Handle)
	}
	if handle != plan.Name {
		return fmt.Errorf("did:aw %s is already bound to handle %s", plan.DIDAW, handle)
	}
	return nil
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

func normalizeIDCreateDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	switch {
	case value == "":
		return "", usageError("--domain is required")
	case strings.Contains(value, "/"):
		return "", usageError("--domain must not contain '/'")
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
