package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idNamespaceCheckTXTOutput struct {
	Status          string `json:"status"`
	Domain          string `json:"domain"`
	DNSName         string `json:"dns_name"`
	DNSController   string `json:"dns_controller"`
	LocalController string `json:"local_controller"`
	RegistryURL     string `json:"registry_url"`
	Inherited       bool   `json:"inherited"`
}

type idNamespaceCheckTXTOptions struct {
	Domain        string
	ControllerKey string
	TXTResolver   awid.TXTResolver
}

var (
	idNamespaceCheckTXTDomain        string
	idNamespaceCheckTXTControllerKey string
	idNamespaceCheckTXTCmd           = &cobra.Command{
		Use:   "check-txt",
		Short: "Verify the _awid DNS TXT record matches the local namespace controller key",
		Long: "Verify the _awid DNS TXT record matches the local namespace controller key.\n\n" +
			"This is read-only. It looks up _awid.<domain>, loads the local namespace\n" +
			"controller key from ~/.awid/controllers/<domain>.key (or --controller-key),\n" +
			"and fails if DNS has not propagated or points at a different controller DID.",
		RunE: runIDNamespaceCheckTXT,
	}
)

func init() {
	idNamespaceCheckTXTCmd.Flags().StringVar(&idNamespaceCheckTXTDomain, "domain", "", "Namespace domain")
	idNamespaceCheckTXTCmd.Flags().StringVar(&idNamespaceCheckTXTControllerKey, "controller-key", "", "Namespace controller key path override")
	idNamespaceCmd.AddCommand(idNamespaceCheckTXTCmd)
}

func runIDNamespaceCheckTXT(cmd *cobra.Command, args []string) error {
	out, err := executeIDNamespaceCheckTXT(idNamespaceCheckTXTOptions{
		Domain:        idNamespaceCheckTXTDomain,
		ControllerKey: idNamespaceCheckTXTControllerKey,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespaceCheckTXT)
	return nil
}

func executeIDNamespaceCheckTXT(opts idNamespaceCheckTXTOptions) (idNamespaceCheckTXTOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idNamespaceCheckTXTOutput{}, err
	}

	key, err := loadIDNamespaceCheckTXTKey(domain, opts.ControllerKey)
	if err != nil {
		return idNamespaceCheckTXTOutput{}, err
	}
	localController := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	authority, err := awid.VerifyExactDomainAuthority(ctx, opts.TXTResolver, domain)
	if err != nil {
		return idNamespaceCheckTXTOutput{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	dnsController := strings.TrimSpace(authority.ControllerDID)
	if dnsController != localController {
		return idNamespaceCheckTXTOutput{}, fmt.Errorf("DNS controller %s does not match local controller %s", dnsController, localController)
	}

	return idNamespaceCheckTXTOutput{
		Status:          "matched",
		Domain:          domain,
		DNSName:         authority.DNSName,
		DNSController:   dnsController,
		LocalController: localController,
		RegistryURL:     strings.TrimSpace(authority.RegistryURL),
		Inherited:       authority.Inherited,
	}, nil
}

func loadIDNamespaceCheckTXTKey(domain, path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) != "" {
		return awid.LoadSigningKey(strings.TrimSpace(path))
	}
	key, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return nil, fmt.Errorf("load namespace controller key for %s: %w (run `aw id namespace prepare-controller --domain %s` first)", domain, err, domain)
	}
	return key, nil
}

func formatIDNamespaceCheckTXT(v any) string {
	out := v.(idNamespaceCheckTXTOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Domain))
	sb.WriteString(fmt.Sprintf("DNS Name:    %s\n", out.DNSName))
	sb.WriteString(fmt.Sprintf("Controller:  %s\n", out.DNSController))
	sb.WriteString(fmt.Sprintf("Local Key:   %s\n", out.LocalController))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	if out.Inherited {
		sb.WriteString("Inherited:   true\n")
	}
	return sb.String()
}
