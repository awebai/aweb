package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw who answers who stands behind the current identity
// (docs/id-certificates.md §5): its installed chain, verified by the shared
// verifier on current status from the registry its domain's _awid record
// names. Only a verified chain is shown.

var whoCmd = &cobra.Command{
	Use:   "who",
	Short: "Show the human behind the current identity, verified through its ID chain",
	Long: `Verify the current identity's installed ID chain on current status from
its namespace's registry, and show the outcome: the nearest human, no human
(no human in its chain), unknown or unavailable, with the verifier's reason. The chain is shown only when it verifies.`,
	Args: cobra.NoArgs,
	RunE: runWho,
}

func init() {
	whoCmd.Flags().StringVar(&whoRegistry, "registry", "", "Registry origin, when the domain's _awid record names none (a record naming api.awid.ai counts as naming none)")
	rootCmd.AddCommand(whoCmd)
}

var whoRegistry string

type whoOptions struct {
	WorkingDir  string
	RegistryURL string
	TXTResolver awid.TXTResolver
}

// whoLink is one verified certificate of the chain, root side first.
type whoLink struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type whoOutput struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	awid.IDChainResult
	Chain []whoLink `json:"chain,omitempty"`
}

func runWho(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	out, err := executeWho(cmd.Context(), whoOptions{WorkingDir: wd, RegistryURL: whoRegistry, TXTResolver: &awid.NetTXTResolver{}})
	if err != nil {
		return err
	}
	printOutput(out, formatWho)
	return nil
}

func executeWho(ctx context.Context, opts whoOptions) (whoOutput, error) {
	identity, err := resolveIdentityForDir(opts.WorkingDir)
	if err != nil {
		return whoOutput{}, err
	}
	id := identity.StableID
	if id == "" {
		id = identity.DID
	}
	domain := identity.Domain
	installed, err := awconfig.LoadInstalledIDChain(filepath.Dir(identity.IdentityPath))
	if err != nil {
		return whoOutput{}, err
	}
	var bundle map[string]any
	if installed != nil {
		bundle = installed.Bundle
		if domain == "" {
			// A local identity has no address: its namespace is the one its
			// chain claims, which the verifier checks against that domain's
			// DNS root.
			certificates := bundle["certificates"].([]any)
			domain, _ = certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)["domain"].(string)
		}
	}
	subject := awid.IDChainSubject{ID: id, DIDKey: identity.DID}
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	status := awid.NewIDStatusClient(registry, opts.TXTResolver)
	if strings.TrimSpace(opts.RegistryURL) != "" {
		authority, err := awid.VerifyExactDomainAuthority(ctx, opts.TXTResolver, domain)
		if err != nil {
			return whoOutput{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
		}
		registryURL, err := domainRegistryURL(authority, opts.RegistryURL)
		if err != nil {
			return whoOutput{}, err
		}
		status = idStatusAt(registry, opts.TXTResolver, registryURL)
	}
	evidence := status.IDChainEvidence(ctx, bundle, subject, domain)
	out := whoOutput{ID: id, Domain: domain, IDChainResult: awid.VerifyIDChain(bundle, subject, evidence, domain)}
	if out.IdentityValid != nil && *out.IdentityValid {
		for _, c := range bundle["certificates"].([]any) {
			certificate := c.(map[string]any)["certificate"].(map[string]any)
			out.Chain = append(out.Chain, whoLink{ID: certificate["id"].(string), Kind: certificate["kind"].(string)})
		}
	}
	return out, nil
}

func formatWho(v any) string {
	out := v.(whoOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", out.ID)
	switch out.Outcome {
	case "nearest_human":
		fmt.Fprintf(&b, "Nearest human: %s\n", *out.HumanID)
	case "no_human":
		fmt.Fprintf(&b, "No human: no human in its chain\n")
	default:
		fmt.Fprintf(&b, "Human: %s (%s)\n", out.Outcome, out.Reason)
	}
	if len(out.Chain) > 0 {
		fmt.Fprintf(&b, "Chain: %s", out.Domain)
		for _, link := range out.Chain {
			fmt.Fprintf(&b, " -> %s (%s)", link.ID, link.Kind)
		}
		b.WriteString("\n")
	}
	return b.String()
}
