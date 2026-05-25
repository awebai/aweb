package main

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idNamespacePrepareControllerOutput struct {
	Status         string `json:"status"`
	Domain         string `json:"domain"`
	ControllerDID  string `json:"controller_did"`
	ControllerKey  string `json:"controller_key"`
	ControllerMeta string `json:"controller_meta"`
	RegistryURL    string `json:"registry_url"`
	DNSName        string `json:"dns_name"`
	DNSValue       string `json:"dns_value"`
}

type idNamespacePrepareControllerOptions struct {
	Domain      string
	RegistryURL string
	Now         func() time.Time
}

var (
	idNamespacePrepareControllerDomain      string
	idNamespacePrepareControllerRegistryURL string
	idNamespacePrepareControllerCmd         = &cobra.Command{
		Use:   "prepare-controller",
		Short: "Create or show a local namespace controller key and DNS TXT value",
		Long: "Create or show a local namespace controller key and DNS TXT value.\n\n" +
			"This command is deliberately local-only: it writes the namespace controller\n" +
			"key under ~/.config/aw/controllers and prints the _awid TXT record to publish.\n" +
			"It does not call AWID, create a did:aw identity, claim an address, create a\n" +
			"team, or modify aweb Cloud state.",
		RunE: runIDNamespacePrepareController,
	}
)

func init() {
	idNamespacePrepareControllerCmd.Flags().StringVar(&idNamespacePrepareControllerDomain, "domain", "", "Namespace domain")
	idNamespacePrepareControllerCmd.Flags().StringVar(&idNamespacePrepareControllerRegistryURL, "registry", "", "Registry origin to place in the DNS TXT record (default: api.awid.ai or AWID_REGISTRY_URL)")
	idNamespaceCmd.AddCommand(idNamespacePrepareControllerCmd)
}

func runIDNamespacePrepareController(cmd *cobra.Command, args []string) error {
	out, err := executeIDNamespacePrepareController(idNamespacePrepareControllerOptions{
		Domain:      idNamespacePrepareControllerDomain,
		RegistryURL: idNamespacePrepareControllerRegistryURL,
		Now:         time.Now,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespacePrepareController)
	return nil
}

func executeIDNamespacePrepareController(opts idNamespacePrepareControllerOptions) (idNamespacePrepareControllerOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idNamespacePrepareControllerOutput{}, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return idNamespacePrepareControllerOutput{}, err
	}
	if strings.TrimSpace(opts.RegistryURL) != "" {
		if err := registry.SetFallbackRegistryURL(opts.RegistryURL); err != nil {
			return idNamespacePrepareControllerOutput{}, fmt.Errorf("invalid --registry: %w", err)
		}
	}
	registryURL := strings.TrimSpace(registry.DefaultRegistryURL)
	if registryURL == "" {
		registryURL = awid.DefaultAWIDRegistryURL
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	createdAt := now().UTC().Format(time.RFC3339)
	key, controllerDID, created, err := resolveOrCreateControllerKey(domain, registryURL, createdAt)
	if err != nil {
		return idNamespacePrepareControllerOutput{}, err
	}
	if key == nil {
		return idNamespacePrepareControllerOutput{}, fmt.Errorf("controller key for %s was not created or loaded", domain)
	}
	if controllerDID == "" {
		controllerDID = awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}

	keyPath, err := awconfig.ControllerKeyPath(domain)
	if err != nil {
		return idNamespacePrepareControllerOutput{}, err
	}
	metaPath, err := awconfig.ControllerMetaPath(domain)
	if err != nil {
		return idNamespacePrepareControllerOutput{}, err
	}
	status := "existing"
	if created {
		status = "prepared"
	}

	return idNamespacePrepareControllerOutput{
		Status:         status,
		Domain:         domain,
		ControllerDID:  controllerDID,
		ControllerKey:  keyPath,
		ControllerMeta: metaPath,
		RegistryURL:    registryURL,
		DNSName:        awid.AWIDTXTName(domain),
		DNSValue:       idCreateDNSRecordValue(controllerDID, registryURL),
	}, nil
}

func formatIDNamespacePrepareController(v any) string {
	out := v.(idNamespacePrepareControllerOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Domain))
	sb.WriteString(fmt.Sprintf("Controller:  %s\n", out.ControllerDID))
	sb.WriteString(fmt.Sprintf("Key:         %s\n", out.ControllerKey))
	sb.WriteString(fmt.Sprintf("Meta:        %s\n", out.ControllerMeta))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	sb.WriteString("DNS TXT:\n")
	sb.WriteString(fmt.Sprintf("  Name:  %s\n", out.DNSName))
	sb.WriteString(fmt.Sprintf("  Value: %s\n", out.DNSValue))
	return sb.String()
}
