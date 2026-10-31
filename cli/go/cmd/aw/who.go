package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw who answers who stands behind the current identity
// (docs/id-certificates.md §5): its installed chain, verified by the shared
// verifier on current status from the registry its domain's _awid record
// names. Only a verified chain is shown.

var whoCmd = &cobra.Command{
	Use:   "who [agent]",
	Short: "Show the verified human behind an identity or a received message sender",
	Long: `Verify the current identity's installed ID chain on current status from
its namespace's registry, and show the outcome: the nearest human, no human
(no human in its chain), unknown or unavailable, with the verifier's reason. The chain is shown only when it verifies.

With an agent address, did:aw or local alias, inspect that sender's most recent
received mail (or chat). Use --message-id for an exact mail, or --session-id
with an optional --message-id for chat. These reads do not acknowledge messages.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runWho,
}

func init() {
	whoCmd.Flags().StringVar(&whoRegistry, "registry", "", "Registry origin, when the domain's _awid record names none (a record naming api.awid.ai counts as naming none)")
	whoCmd.Flags().StringVar(&whoMessageID, "message-id", "", "Inspect the sender of this received mail or chat message")
	whoCmd.Flags().StringVar(&whoSessionID, "session-id", "", "Inspect received chat in this session")
	rootCmd.AddCommand(whoCmd)
}

var whoRegistry, whoMessageID, whoSessionID string

type whoStatus interface {
	IDChainEvidence(context.Context, map[string]any, awid.IDChainSubject, string) *awid.IDChainEvidence
}

type whoOptions struct {
	ReceivedEnrollment func(context.Context, string, string) awid.IDTreeEnrollmentResult
	Status             whoStatus
	WorkingDir         string
	RegistryURL        string
	TXTResolver        awid.TXTResolver
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
	opts := whoOptions{WorkingDir: wd, RegistryURL: whoRegistry, TXTResolver: &awid.NetTXTResolver{}}
	var out whoOutput
	if len(args) > 0 || whoMessageID != "" || whoSessionID != "" {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		c, sel, resolveErr := resolveClientSelectionForDir(wd)
		if resolveErr != nil {
			return resolveErr
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		target := ""
		if len(args) > 0 {
			target = strings.TrimSpace(args[0])
		}
		opts.ReceivedEnrollment = c.Client.ReceivedIDTreeEnrollment
		message, readErr := findWhoSender(ctx, c.Client, target, whoMessageID, whoSessionID)
		if readErr != nil {
			return readErr
		}
		if message.FromAddress != "" {
			opts.ReceivedEnrollment = func(ctx context.Context, id, key string) awid.IDTreeEnrollmentResult {
				return c.Client.ReceivedAddressIDTreeEnrollment(ctx, message.FromAddress, id, key)
			}
		}
		out, err = executeWhoReceived(ctx, message, opts)
	} else {
		out, err = executeWho(cmd.Context(), opts)
	}
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
		// An address is an alias, independent of the signed ancestry domain.
		// The shared verifier checks this claim against current DNS/status.
		certificates := bundle["certificates"].([]any)
		domain, _ = certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)["domain"].(string)
	} else if strings.HasPrefix(id, "did:aw:") {
		// A chainless did:aw is judged where its key route says it is
		// enrolled, never in its address's domain.
		enrollment := awid.IDTreeEnrollmentResult{State: "unknown"}
		if resolution, err := identityKeyRoute(ctx, identity, ""); err == nil {
			enrollment = resolution.IDTreeEnrollmentOf(id, identity.DID, time.Now())
		}
		switch {
		case enrollment.State == "not_enrolled":
			return whoOutput{ID: id, IDChainResult: awid.IDChainResult{Outcome: "unknown", Reason: "unregistered_identity"}}, nil
		case enrollment.State == "enrolled" && enrollment.Domain != nil:
			domain = *enrollment.Domain
		default:
			return whoOutput{ID: id, IDChainResult: awid.IDChainResult{Outcome: "unavailable", Reason: "evidence_unavailable"}}, nil
		}
	}
	return verifyWhoPresentation(ctx, awid.IDChainSubject{ID: id, DIDKey: identity.DID}, bundle, domain, opts)
}

func verifyWhoPresentation(ctx context.Context, subject awid.IDChainSubject, bundle map[string]any, domain string, opts whoOptions) (whoOutput, error) {
	out := whoOutput{ID: subject.ID, Domain: domain}
	// Refuse malformed or mismatched presentations before DNS/HTTP.
	preflight := awid.VerifyIDChain(bundle, subject, nil, domain)
	if preflight.Reason != "evidence_unavailable" {
		out.IDChainResult = preflight
		return out, nil
	}
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	status := awid.NewIDStatusClient(registry, opts.TXTResolver)
	if strings.TrimSpace(opts.RegistryURL) != "" {
		authority, err := awid.DiscoverAuthoritativeRegistry(ctx, opts.TXTResolver, domain)
		if err != nil {
			return whoOutput{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
		}
		registryURL, err := domainRegistryURL(authority, opts.RegistryURL)
		if err != nil {
			return whoOutput{}, err
		}
		status = idStatusAt(registry, opts.TXTResolver, registryURL)
	}
	reader := whoStatus(status)
	if opts.Status != nil {
		reader = opts.Status
	}
	evidence := reader.IDChainEvidence(ctx, bundle, subject, domain)
	out.IDChainResult = awid.VerifyIDChain(bundle, subject, evidence, domain)
	if out.IdentityValid != nil && *out.IdentityValid && bundle != nil {
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
