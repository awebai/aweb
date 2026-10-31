package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw id namespace reaffirm opens the first ID-tree epoch of a namespace that
// was registered before epochs existed. It exists only until no such
// namespace remains (aweb-acrd, D7 cleanup), and runs only when asked.

type idNamespaceReaffirmEpoch struct {
	Seq          int    `json:"seq"`
	DIDKey       string `json:"did_key"`
	RegisteredAt string `json:"registered_at"`
	Continuity   string `json:"continuity"`
}

type idNamespaceReaffirmOutput struct {
	Status        string                   `json:"status"`
	Domain        string                   `json:"domain"`
	ControllerDID string                   `json:"controller_did"`
	Epoch         idNamespaceReaffirmEpoch `json:"epoch"`
}

type idNamespaceReaffirmOptions struct {
	Domain        string
	ControllerKey string
	RegistryURL   string
	TXTResolver   awid.TXTResolver
}

var (
	idNamespaceReaffirmDomain        string
	idNamespaceReaffirmControllerKey string
	idNamespaceReaffirmRegistry      string
	idNamespaceReaffirmCmd           = &cobra.Command{
		Use:   "reaffirm",
		Short: "Open the ID-tree epoch of a namespace registered before epochs existed",
		Long: "Open the first ID-tree epoch of your own-domain namespace, registered before\n" +
			"epochs existed, by registering it again with its controller key. The registry\n" +
			"opens the epoch only for the controller it already stores, and only when the\n" +
			"_awid.<domain> TXT record names that key. A namespace that has an epoch is\n" +
			"left as it is.",
		Args: cobra.NoArgs,
		RunE: runIDNamespaceReaffirm,
	}
)

func init() {
	idNamespaceReaffirmCmd.Flags().StringVar(&idNamespaceReaffirmDomain, "domain", "", "Namespace domain")
	idNamespaceReaffirmCmd.Flags().StringVar(&idNamespaceReaffirmControllerKey, "controller-key", "", "Namespace controller key path override")
	idNamespaceReaffirmCmd.Flags().StringVar(&idNamespaceReaffirmRegistry, "registry", "", "Registry origin override")
	idNamespaceCmd.AddCommand(idNamespaceReaffirmCmd)
}

func runIDNamespaceReaffirm(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	out, err := executeIDNamespaceReaffirm(ctx, idNamespaceReaffirmOptions{
		Domain:        idNamespaceReaffirmDomain,
		ControllerKey: idNamespaceReaffirmControllerKey,
		RegistryURL:   idNamespaceReaffirmRegistry,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespaceReaffirm)
	return nil
}

func executeIDNamespaceReaffirm(ctx context.Context, opts idNamespaceReaffirmOptions) (idNamespaceReaffirmOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, true)
	if err != nil {
		return idNamespaceReaffirmOutput{}, err
	}
	if domain == implicitLocalDomain {
		return idNamespaceReaffirmOutput{}, usageError("the local namespace has no DNS authority and no ID-tree epoch; there is nothing to reaffirm")
	}
	key, err := loadIDNamespaceReaffirmKey(domain, opts.ControllerKey)
	if err != nil {
		return idNamespaceReaffirmOutput{}, err
	}
	controllerDID := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))

	authority, err := awid.DiscoverAuthoritativeRegistry(ctx, opts.TXTResolver, domain)
	if err != nil {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	// The configured registry (AWID_REGISTRY_URL), as other namespace
	// commands use, and --registry over it.
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	if err := configureEmbeddedRegistryBaseURL("", registry.SetFallbackRegistryURL); err != nil {
		return idNamespaceReaffirmOutput{}, err
	}
	if override := strings.TrimSpace(opts.RegistryURL); override != "" {
		if err := registry.SetFallbackRegistryURL(override); err != nil {
			return idNamespaceReaffirmOutput{}, fmt.Errorf("invalid registry URL: %w", err)
		}
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("discover registry for %s: %w", domain, err)
	}
	if strings.TrimSpace(opts.RegistryURL) != "" {
		registryURL = registry.DefaultRegistryURL
	}
	status := awid.NewIDStatusClient(registry, opts.TXTResolver)
	status.Route = func(context.Context, string) (string, error) { return registryURL, nil }
	// A namespace with no current root, which is every pre-epoch namespace,
	// has no status to read; one with a current root is already enrolled.
	epochs, err := namespaceEpochs(ctx, status, domain)
	if err != nil && !errors.Is(err, errNoCurrentRoot) {
		return idNamespaceReaffirmOutput{}, err
	}
	if open, ok := openNamespaceEpoch(epochs); ok {
		return idNamespaceReaffirmOutput{Status: "already_enrolled", Domain: domain, ControllerDID: controllerDID, Epoch: open}, nil
	}

	// The registry opens the epoch only with exact DNS for the stored
	// controller; refuse before any write when either is not this key.
	if authority.Inherited || authority.DNSName != awid.AWIDTXTName(domain) {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("no own-domain TXT record at %s; publish \"%s\" there before reaffirming", awid.AWIDTXTName(domain), idCreateDNSRecordValue(controllerDID, ""))
	}
	if dns := strings.TrimSpace(authority.ControllerDID); dns != controllerDID {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("%s names %s, not this controller key %s; the registry opens an epoch only when DNS names the controller", awid.AWIDTXTName(domain), dns, controllerDID)
	}
	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("fetch namespace %s: %w", domain, err)
	}
	if stored := strings.TrimSpace(namespace.ControllerDID); stored != controllerDID {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("the registry stores controller %s for %s, not this key %s; reaffirmation applies only to the stored controller. To move the namespace to this key, use aw id namespace rotate-controller --domain %s", stored, domain, controllerDID, domain)
	}

	if _, err := registry.RegisterNamespaceAt(ctx, registryURL, domain, controllerDID, key); err != nil {
		return idNamespaceReaffirmOutput{}, fmt.Errorf("register %s: %w", domain, err)
	}
	// A successful registration does not prove an epoch opened: read it back.
	notOpened := fmt.Errorf("the registry did not open an epoch for %s; it opens only a missing first epoch for the stored controller with exact DNS (or the registry is older than AWID 0.5.35)", domain)
	epochs, err = namespaceEpochs(ctx, status, domain)
	if errors.Is(err, errNoCurrentRoot) {
		return idNamespaceReaffirmOutput{}, notOpened
	}
	if err != nil {
		return idNamespaceReaffirmOutput{}, err
	}
	open, ok := openNamespaceEpoch(epochs)
	if !ok || len(epochs) != 1 || open.Seq != 1 || open.DIDKey != controllerDID || open.Continuity != "replaced" {
		return idNamespaceReaffirmOutput{}, notOpened
	}
	return idNamespaceReaffirmOutput{Status: "opened", Domain: domain, ControllerDID: controllerDID, Epoch: open}, nil
}

func loadIDNamespaceReaffirmKey(domain, path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) != "" {
		return awid.LoadSigningKey(strings.TrimSpace(path))
	}
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, err
	}
	if !exists {
		keyPath, _ := awconfig.ControllerKeyPath(domain)
		return nil, fmt.Errorf("no controller key for %s here (expected at %s); reaffirm runs where the namespace's controller key is, and a namespace hosted by a service keeps its key there", domain, keyPath)
	}
	return awconfig.LoadControllerKey(domain)
}

type namespaceEpoch struct {
	idNamespaceReaffirmEpoch
	open bool
}

// errNoCurrentRoot is the registry's answer for a domain with no current
// root: no open epoch for its stored controller with its DNS.
var errNoCurrentRoot = errors.New("the namespace has no current ID-tree root")

// namespaceEpochs reads a namespace's ID-tree epochs from the registry's
// ID-certificate status. The registry answers a domain with no current root
// with 503 evidence_unavailable, reported as errNoCurrentRoot.
func namespaceEpochs(ctx context.Context, status *awid.IDStatusClient, domain string) ([]namespaceEpoch, error) {
	raw, err := status.FetchIDCertificateStatus(ctx, domain, map[string]any{"v": 1, "domain": domain, "ids": []string{}})
	var refused *awid.RegistryError
	if errors.As(err, &refused) && refused.StatusCode == http.StatusServiceUnavailable && refused.Code == "evidence_unavailable" {
		return nil, errNoCurrentRoot
	}
	if err != nil {
		return nil, fmt.Errorf("read ID-tree status for %s: %w", domain, err)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Namespace *struct {
			Epochs []struct {
				Seq          *int    `json:"seq"`
				DIDKey       string  `json:"did_key"`
				RegisteredAt string  `json:"registered_at"`
				RetiredAt    *string `json:"retired_at"`
				Continuity   string  `json:"continuity"`
			} `json:"epochs"`
		} `json:"namespace"`
	}
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.Namespace == nil || snapshot.Namespace.Epochs == nil {
		return nil, errors.New("the registry's ID-tree status has no namespace epochs; it may be older than AWID 0.5.35")
	}
	epochs := make([]namespaceEpoch, 0, len(snapshot.Namespace.Epochs))
	for _, e := range snapshot.Namespace.Epochs {
		if e.Seq == nil || strings.TrimSpace(e.DIDKey) == "" {
			return nil, errors.New("the registry's ID-tree status has a malformed epoch")
		}
		epochs = append(epochs, namespaceEpoch{
			idNamespaceReaffirmEpoch: idNamespaceReaffirmEpoch{Seq: *e.Seq, DIDKey: e.DIDKey, RegisteredAt: e.RegisteredAt, Continuity: e.Continuity},
			open:                     e.RetiredAt == nil,
		})
	}
	return epochs, nil
}

func openNamespaceEpoch(epochs []namespaceEpoch) (idNamespaceReaffirmEpoch, bool) {
	for _, e := range epochs {
		if e.open {
			return e.idNamespaceReaffirmEpoch, true
		}
	}
	return idNamespaceReaffirmEpoch{}, false
}

func formatIDNamespaceReaffirm(v any) string {
	out := v.(idNamespaceReaffirmOutput)
	if out.Status == "already_enrolled" {
		return fmt.Sprintf("%s already has ID-tree epoch %d (controller %s); nothing to do.\n", out.Domain, out.Epoch.Seq, out.Epoch.DIDKey)
	}
	return fmt.Sprintf("%s now has ID-tree epoch %d (controller %s).\n", out.Domain, out.Epoch.Seq, out.Epoch.DIDKey)
}
