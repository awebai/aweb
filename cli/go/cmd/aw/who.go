package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/approval"
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
	whoCmd.Flags().StringVar(&whoRegistry, "registry", "", "Registry origin when neither the identity home nor DNS names a non-default registry")
	whoCmd.Flags().StringVar(&whoMessageID, "message-id", "", "Inspect the sender of this received mail or chat message")
	whoCmd.Flags().StringVar(&whoSessionID, "session-id", "", "Inspect received chat in this session")
	whoCmd.Flags().BoolVar(&whoRoom, "room", false, "Inspect an exact team room post (requires --message-id)")
	rootCmd.AddCommand(whoCmd)
}

var whoRegistry, whoMessageID, whoSessionID string
var whoRoom bool

type whoStatus interface {
	IDChainEvidence(context.Context, map[string]any, awid.IDChainSubject, string) *awid.IDChainEvidence
}

type whoOptions struct {
	EvidenceTrust      evidenceTrust
	ReceivedEnrollment func(context.Context, string, string) awid.IDTreeEnrollmentResult
	Status             whoStatus
	WorkingDir         string
	RegistryURL        string
	TXTResolver        awid.TXTResolver
	ownIdentity        *awconfig.ResolvedIdentity
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
	Chain         []whoLink                 `json:"chain,omitempty"`
	Evidence      []approval.EvidenceReport `json:"evidence,omitempty"`
	registryError error
}

func runWho(cmd *cobra.Command, args []string) error {
	if whoRoom && (whoMessageID == "" || whoSessionID != "") {
		return fmt.Errorf("--room requires --message-id and cannot be combined with --session-id")
	}
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
		if !whoRoom {
			if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
				return err
			}
		}
		target := ""
		if len(args) > 0 {
			target = strings.TrimSpace(args[0])
		}
		opts.ReceivedEnrollment = c.Client.ReceivedIDTreeEnrollment
		var message awid.InboxMessage
		var readErr error
		if whoRoom {
			message, readErr = findWhoRoomSender(ctx, c.Client, target, whoMessageID)
		} else {
			message, readErr = findWhoSender(ctx, c.Client, target, whoMessageID, whoSessionID)
		}
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
	installed, err := awconfig.LoadInstalledIDChain(filepath.Dir(identity.SigningKeyPath))
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
	}
	opts.ownIdentity = identity
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
	registry := newAWIDRegistryClient(nil, opts.TXTResolver)
	reader := opts.Status
	scope := identityRegistryScope{identity: opts.ownIdentity, domain: domain}
	if opts.ownIdentity == nil {
		scope = selectedIdentityRegistryScope(opts.WorkingDir)
	}
	private := recordedPrivateIdentityRegistry(scope.identity) != "" && (opts.ownIdentity != nil || scope.applies(domain))
	var route identityEvidenceRoute
	if reader == nil && domain != "" && (bundle != nil || opts.RegistryURL != "") {
		var err error
		route, err = resolveIdentityEvidenceRoute(ctx, registry, opts.TXTResolver, scope, domain, opts.RegistryURL)
		if err != nil {
			var refusal *cliError
			if opts.RegistryURL != "" || errors.As(err, &refusal) {
				return whoOutput{}, err
			}
			out.IDChainResult = preflight
			return out, nil
		}
		reader = route.status(registry)
	}
	if strings.HasPrefix(subject.ID, "did:aw:") {
		enrollment := awid.IDTreeEnrollmentResult{State: "unknown"}
		if private && route.origin != "" && opts.ownIdentity == nil {
			if route.authority.ControllerDID != "" {
				enrollment = keyRouteEnrollment(ctx, registry, route.origin, subject)
			}
		} else if opts.ReceivedEnrollment != nil {
			enrollment = opts.ReceivedEnrollment(ctx, subject.ID, subject.DIDKey)
		} else if opts.ownIdentity != nil {
			if private {
				if bundle == nil {
					origin, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
						Kind: registryIdentityEvidenceRoute, Identity: opts.ownIdentity, Override: opts.RegistryURL,
					})
					if err != nil {
						return whoOutput{}, err
					}
					trustRecordedRegistryOrigin(registry.Resolver, origin, opts.ownIdentity.RegistryOperatorOrigin)
					route.origin = origin
				}
				if route.authority.ControllerDID != "" || bundle == nil {
					enrollment = keyRouteEnrollment(ctx, registry, route.origin, subject)
				}
			} else if key, err := identityKeyRoute(ctx, opts.ownIdentity, ""); err == nil {
				enrollment = key.IDTreeEnrollmentOf(subject.ID, subject.DIDKey, time.Now())
			}
		}
		switch {
		case enrollment.State == "not_enrolled":
			return whoOutput{ID: subject.ID, IDChainResult: awid.IDChainResult{Outcome: "unknown", Reason: "unregistered_identity"}}, nil
		case enrollment.State == "enrolled" && enrollment.Domain != nil:
			domain = *enrollment.Domain
			out.Domain = domain
		default:
			return whoOutput{ID: subject.ID, IDChainResult: awid.IDChainResult{Outcome: "unavailable", Reason: "evidence_unavailable"}}, nil
		}
		// The shared primitive already enforces presentation-domain agreement.
		// Supply the independently obtained enrollment domain on every global
		// presentation, not just when the sender omitted its chain.
		preflight = awid.VerifyIDChain(bundle, subject, nil, domain)
		if preflight.Reason != "evidence_unavailable" {
			out.IDChainResult = preflight
			return out, nil
		}
	}
	if reader == nil && private {
		scope.domain = domain
		route, err := resolveIdentityEvidenceRoute(ctx, registry, opts.TXTResolver, scope, domain, opts.RegistryURL)
		if err != nil {
			var refusal *cliError
			if errors.As(err, &refusal) {
				return whoOutput{}, err
			}
			out.IDChainResult = preflight
			return out, nil
		}
		reader = route.status(registry)
	}
	if reader == nil {
		reader = awid.NewIDStatusClient(registry, opts.TXTResolver)
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

func keyRouteEnrollment(ctx context.Context, registry *awid.RegistryClient, origin string, subject awid.IDChainSubject) awid.IDTreeEnrollmentResult {
	key, err := registry.ResolveKeyAt(ctx, origin, subject.ID)
	if err != nil {
		return awid.IDTreeEnrollmentResult{State: "unknown"}
	}
	return key.IDTreeEnrollmentOf(subject.ID, subject.DIDKey, time.Now())
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
