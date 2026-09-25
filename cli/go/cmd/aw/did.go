package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var identityLogCmd = &cobra.Command{
	Use:   "log [did_aw|address]",
	Short: "Show a global AWID DID log",
	Long: "Show the AWID registry DID log for a global identity. The log records DID registration and key-rotation entries, verifies the returned chain, and reports the current did:key head.\n\n" +
		"Without arguments, the command reads the current global identity's did:aw. An explicit target may be a did:aw or a global address in <domain>/<name> form, which is resolved through the registry before reading its DID log. Local identities do not have registry-backed history; the command returns unsupported_registry_history for a current local identity instead of inventing hosted history.\n\n" +
		"With --json, status is OK for a verified log, BROKEN for unverifiable log data or address/log key mismatch, UNREACHABLE for registry fetch failures, and unsupported_registry_history for local identities.",
	Args: cobra.MaximumNArgs(1),
	RunE: runDidLog,
}

func init() {
	identityCmd.AddCommand(identityLogCmd)
}

type idLogOutput struct {
	Status        string                `json:"status"`
	RegistryURL   string                `json:"registry_url,omitempty"`
	Target        string                `json:"target,omitempty"`
	DIDAW         string                `json:"did_aw,omitempty"`
	CurrentDIDKey string                `json:"current_did_key,omitempty"`
	EntryCount    int                   `json:"entry_count,omitempty"`
	Entries       []awid.DidKeyEvidence `json:"entries,omitempty"`
	Error         string                `json:"error,omitempty"`
	Remedy        string                `json:"remedy,omitempty"`
}

func runDidLog(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workingDir, _ := os.Getwd()
	out, err := loadDIDLog(ctx, workingDir, args)
	if err != nil {
		return err
	}
	if jsonFlag {
		printJSON(out)
		return nil
	}
	fmt.Print(formatIDLog(out))
	return nil
}

func loadDIDLog(ctx context.Context, workingDir string, args []string) (idLogOutput, error) {
	registry, identity, err := resolveRegistryClientForLookup(workingDir)
	if err != nil {
		return idLogOutput{}, err
	}
	registry.RequestID = newRegistryReadRequestID()

	target := "current identity"
	didAW := ""
	registryURL := ""
	currentDIDFromAddress := ""
	if len(args) == 0 {
		if identity == nil {
			return idLogOutput{}, usageError("aw id log requires a global identity or an explicit did:aw / <domain>/<name> address")
		}
		if awid.NormalizeIdentityScope(identity.IdentityScope) != awid.IdentityModeGlobal || strings.TrimSpace(identity.StableID) == "" {
			return unsupportedLocalIdentityLog(identity), nil
		}
		didAW = strings.TrimSpace(identity.StableID)
		target = didAW
		registryURL, err = currentIdentityRegistryURL(ctx, identity, registry)
		if err != nil {
			return idLogOutput{}, err
		}
	} else {
		target = strings.TrimSpace(args[0])
		if strings.HasPrefix(target, "did:aw:") {
			didAW = target
			registryURL, err = registryLookupURL(ctx, registry, identity, didAW)
			if err != nil {
				return idLogOutput{}, err
			}
		} else {
			domain, name, ok := awconfig.CutIdentityAddress(target)
			if !ok {
				return idLogOutput{}, usageError("address must be did:aw or <domain>/<name>")
			}
			domain = awconfig.NormalizeDomain(domain)
			if identity != nil && awconfig.NormalizeDomain(identity.Domain) == domain && strings.TrimSpace(identity.RegistryURL) != "" {
				registryURL = strings.TrimSpace(identity.RegistryURL)
			} else {
				registryURL, err = registry.DiscoverRegistry(ctx, domain)
				if err != nil {
					return idLogOutput{}, err
				}
			}
			address, _, err := registry.GetNamespaceAddressAt(ctx, registryURL, domain, name)
			if err != nil {
				return idLogOutput{Status: "UNREACHABLE", RegistryURL: registryURL, Target: target, Error: err.Error()}, nil
			}
			didAW = strings.TrimSpace(address.DIDAW)
			currentDIDFromAddress = strings.TrimSpace(address.CurrentDIDKey)
			if didAW == "" {
				return idLogOutput{Status: "BROKEN", RegistryURL: registryURL, Target: target, Error: "address has no did:aw"}, nil
			}
		}
	}

	entries, err := registry.GetDIDLog(ctx, registryURL, didAW)
	if err != nil {
		return idLogOutput{Status: "UNREACHABLE", RegistryURL: registryURL, Target: target, DIDAW: didAW, Error: err.Error()}, nil
	}
	head, verifyErr := awid.VerifyDidLogEntries(didAW, entries, time.Now().UTC())
	out := idLogOutput{Status: "OK", RegistryURL: registryURL, Target: target, DIDAW: didAW, EntryCount: len(entries), Entries: entries}
	if verifyErr != nil {
		out.Status = "BROKEN"
		out.Error = verifyErr.Error()
		return out, nil
	}
	out.CurrentDIDKey = strings.TrimSpace(head.CurrentDIDKey)
	if currentDIDFromAddress != "" && out.CurrentDIDKey != currentDIDFromAddress {
		out.Status = "BROKEN"
		out.Error = fmt.Sprintf("address current did:key %q does not match verified log head %q", currentDIDFromAddress, out.CurrentDIDKey)
	}
	return out, nil
}

func unsupportedLocalIdentityLog(identity *awconfig.ResolvedIdentity) idLogOutput {
	did := ""
	if identity != nil {
		did = strings.TrimSpace(identity.DID)
	}
	return idLogOutput{
		Status: "unsupported_registry_history",
		Target: did,
		Error:  "local identities do not have a registry-backed DID audit log",
		Remedy: "Use `aw id show` for the local identity summary. Global identity history is available through AWID DID logs (`aw id log <did:aw>` or `aw id verify <did:aw>`).",
	}
}

func formatIDLog(out idLogOutput) string {
	if out.Status == "unsupported_registry_history" {
		return fmt.Sprintf("Status: unsupported_registry_history\nError:  %s\nRemedy: %s\n", out.Error, out.Remedy)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Status:      %s\n", out.Status)
	if out.RegistryURL != "" {
		fmt.Fprintf(&b, "Registry:    %s\n", out.RegistryURL)
	}
	if out.Target != "" {
		fmt.Fprintf(&b, "Target:      %s\n", out.Target)
	}
	if out.DIDAW != "" {
		fmt.Fprintf(&b, "DID AW:      %s\n", out.DIDAW)
	}
	if out.CurrentDIDKey != "" {
		fmt.Fprintf(&b, "Current key: %s\n", out.CurrentDIDKey)
	}
	if out.Error != "" {
		fmt.Fprintf(&b, "Error:       %s\n", out.Error)
	}
	fmt.Fprintf(&b, "Entries:     %d\n", out.EntryCount)
	for _, e := range out.Entries {
		fmt.Fprintf(&b, "[%d] %s %s\n", e.Seq, e.Operation, e.Timestamp)
		if e.PreviousDIDKey != nil && strings.TrimSpace(*e.PreviousDIDKey) != "" {
			fmt.Fprintf(&b, "  previous_did_key: %s\n", strings.TrimSpace(*e.PreviousDIDKey))
		}
		fmt.Fprintf(&b, "  new_did_key:      %s\n", e.NewDIDKey)
		fmt.Fprintf(&b, "  authorized_by:    %s\n", e.AuthorizedBy)
		fmt.Fprintf(&b, "  entry_hash:       %s\n", e.EntryHash)
	}
	return b.String()
}
