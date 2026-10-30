package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	idRevokeCutoffFlag string

	idRevokeCmd = &cobra.Command{
		Use:   "revoke <did:aw>",
		Short: "Revoke a registered identity's ID-tree authority",
		Long: "Revoke a registered identity under docs/id-certificates.md §3, signed by\n" +
			"the current identity (itself, or its current child), by --human <did:aw>\n" +
			"--domain D for a human on this machine, or by --as-root --domain D for the\n" +
			"namespace root. AWID decides whether the signer may revoke the identity.\n" +
			"The revocation takes effect at AWID's serialization time; only --as-root\n" +
			"may set an earlier --cutoff. This revokes ID-tree authority, not team\n" +
			"membership, addresses or DID key history.",
		Args: cobra.ExactArgs(1),
		RunE: runIDRevoke,
	}
)

func init() {
	idRevokeCmd.Flags().BoolVar(&idChildAsRoot, "as-root", false, "Revoke as the namespace root, with this machine's controller key")
	idRevokeCmd.Flags().StringVar(&idChildDomain, "domain", "", "Namespace domain (with --as-root or --human)")
	idRevokeCmd.Flags().StringVar(&idChildHuman, "human", "", "Revoke as this human on this machine (did:aw)")
	idRevokeCmd.Flags().StringVar(&idChildRegistry, "registry", "", "Registry origin for --as-root, when the domain's _awid record names none")
	idRevokeCmd.Flags().StringVar(&idRevokeCutoffFlag, "cutoff", "", "With --as-root: the earlier time (RFC 3339) the revocation takes effect from")
	identityCmd.AddCommand(idRevokeCmd)
}

type idRevokeOutput struct {
	ID            string `json:"id"`
	Domain        string `json:"domain"`
	RevokedAt     string `json:"revoked_at"`
	EffectiveFrom string `json:"effective_from"`
}

func runIDRevoke(cmd *cobra.Command, args []string) error {
	out, err := executeIDRevoke(cmd.Context(), idChildOptionsFromFlags(), args[0], idRevokeCutoffFlag)
	if err != nil {
		return err
	}
	printOutput(out, formatIDRevoke)
	return nil
}

// executeIDRevoke revokes target with the selected signer, against the
// target's current head as its registry reports it now, so a repeat is
// checked against the same head.
func executeIDRevoke(ctx context.Context, opts idChildOptions, target, cutoff string) (idRevokeOutput, error) {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "did:aw:") {
		return idRevokeOutput{}, usageError("only a registered did:aw has a portable revocation; %q is not one", target)
	}
	var effectiveFrom *string
	if cutoff != "" {
		if !opts.Issuer.AsRoot {
			return idRevokeOutput{}, usageError("only --as-root may set --cutoff; any other signer revokes from AWID's serialization time")
		}
		wire, err := idRevokeWireTime(cutoff)
		if err != nil {
			return idRevokeOutput{}, err
		}
		effectiveFrom = &wire
	}
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return idRevokeOutput{}, err
	}
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	registry.DefaultRegistryURL = issuer.registryURL
	head, err := idRevokeHead(ctx, idStatusAt(registry, opts.TXTResolver, issuer.registryURL), issuer.domain, target)
	if err != nil {
		return idRevokeOutput{}, err
	}
	if issuer.kind == "human" {
		if err := opts.HumanAtTerminal(); err != nil {
			return idRevokeOutput{}, fmt.Errorf("revoking as human %s needs that human at the terminal: %w", issuer.human, err)
		}
	}
	answer, err := registry.RevokeIDCertificateAt(ctx, issuer.registryURL, issuer.domain, target, issuer.signer("revoke "+target), &head, effectiveFrom)
	if err != nil {
		return idRevokeOutput{}, fmt.Errorf("revoke %s: %w", target, err)
	}
	revokedAt, _ := answer["revoked_at"].(string)
	effective, _ := answer["effective_from"].(string)
	if revokedAt == "" || effective == "" {
		return idRevokeOutput{}, fmt.Errorf("revoke %s: the registry answered without revoked_at and effective_from", target)
	}
	return idRevokeOutput{ID: target, Domain: issuer.domain, RevokedAt: revokedAt, EffectiveFrom: effective}, nil
}

// idRevokeHead is target's current certificate id in domain's status now.
func idRevokeHead(ctx context.Context, status *awid.IDStatusClient, domain, target string) (string, error) {
	answer, err := status.FetchIDCertificateStatus(ctx, domain, map[string]any{"v": 1, "domain": domain, "ids": []any{target}})
	if err != nil {
		return "", fmt.Errorf("read the status of %s: %w", target, err)
	}
	if missing, _ := answer["missing"].([]any); len(missing) > 0 {
		return "", fmt.Errorf("%s is not registered in %s, so it has no portable revocation", target, domain)
	}
	rows, _ := answer["identities"].([]any)
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if row["id"] != target {
			continue
		}
		if head, _ := row["current_certificate_id"].(string); head != "" {
			return head, nil
		}
	}
	return "", fmt.Errorf("read the status of %s: %w", target, awid.ErrMalformedIDStatus)
}

// idRevokeWireTime is an RFC 3339 time as AWID's wire time: UTC with
// microseconds.
func idRevokeWireTime(value string) (string, error) {
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return "", usageError("--cutoff must be an RFC 3339 time, such as 2026-10-30T08:00:00Z: %v", err)
	}
	return at.UTC().Format("2006-01-02T15:04:05.000000Z"), nil
}

func formatIDRevoke(v any) string {
	out := v.(idRevokeOutput)
	return fmt.Sprintf("Revoked:         %s\nDomain:          %s\nRevoked at:      %s\nEffective from:  %s\n",
		out.ID, out.Domain, out.RevokedAt, out.EffectiveFrom)
}
