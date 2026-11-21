package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const humanCommandAnnotation = "aw.human-participation"

var idHumanRegisterRegistry string
var idHumanRegisterCmd = &cobra.Command{
	Use: "register FILE", Short: "Register your issued human certificate with your own key",
	Long: `Register the certificate handed to you by your organization's operator or
approved issuer. Run this yourself with --human ID --human-domain DOMAIN at a
terminal; unlock once with your keychain passphrase for this command. Prepare your human ID
first with aw id human init. This registers your ID without enrolling an approval
key. Afterwards you may optionally run aw id human enroll, or create a portable
message with aw id proof --message-file FILE for anyone to check with aw verify.`,
	Args: cobra.ExactArgs(1), Annotations: map[string]string{humanCommandAnnotation: "prepared"},
	RunE: func(cmd *cobra.Command, args []string) error {
		activeHuman.operation = "register your issued human certificate"
		raw, err := readFileBounded(args[0], maxResponseBytes)
		if err != nil {
			return err
		}
		chain, err := parseIssuedHumanChain(raw, activeHuman.record)
		if err != nil {
			return err
		}
		out, err := registerHumanChain(cmd.Context(), activeHuman, chain, idHumanRegisterRegistry)
		if err != nil {
			return err
		}
		printOutput(out, func(value any) string {
			out := value.(idHumanInitOutput)
			return fmt.Sprintf("Registered your human ID %s. This command did not enroll an approval key.\nNext: optionally run aw id human enroll, or aw id proof --message-file FILE to share a verifiable message.\n", out.ID)
		})
		return nil
	},
}

func init() {
	idHumanRegisterCmd.Flags().StringVar(&idHumanRegisterRegistry, "registry", "", "Optional registry pin; must agree with the domain's DNS record")
	idHumanCmd.AddCommand(idHumanRegisterCmd)
}

func parseIssuedHumanChain(raw []byte, record *awconfig.HumanRecord) (map[string]any, error) {
	packet, err := proof.Parse(raw)
	if err != nil {
		return nil, err
	}
	var signed map[string]any
	switch packet["state"] {
	case "issued":
		if packet["person"] != record.StableID || packet["identity_key"] != record.DIDKey {
			return nil, usageError("issued certificate names another person or identity key")
		}
		signed, _ = packet["certificate"].(map[string]any)
	case "enrollment_pending":
		intent, _ := packet["intent"].(map[string]any)
		body, _ := intent["intent"].(map[string]any)
		if body["person"] != record.StableID || body["identity_key"] != record.DIDKey {
			return nil, usageError("enrollment intent names another person or identity key")
		}
		signed, _ = body["pending_certificate"].(map[string]any)
	default:
		return nil, usageError("expected an issued certificate or pending enrollment packet")
	}
	certificate, _ := signed["certificate"].(map[string]any)
	issuer, _ := certificate["issuer_key"].(string)
	if certificate["id"] != record.StableID || certificate["domain"] != record.Domain || certificate["kind"] != "human" {
		return nil, usageError("certificate does not name your human ID and domain")
	}
	if err := awid.VerifyIDCertificate(signed, issuer); err != nil {
		return nil, err
	}
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{signed}}
	// Structural checks precede registration. DNS and the registry supply the
	// controller/enrollment authority; the handover file never supplies trust.
	result := awid.VerifyIDChain(chain, awid.IDChainSubject{ID: record.StableID, DIDKey: record.DIDKey}, nil, record.Domain)
	if result.Reason != "evidence_unavailable" {
		return nil, fmt.Errorf("issued chain refused: %s", result.Reason)
	}
	return chain, nil
}

func registerHumanChain(ctx context.Context, human *humanParticipation, chain map[string]any, override string) (idHumanInitOutput, error) {
	certificates, ok := chain["certificates"].([]any)
	if !ok || len(certificates) == 0 {
		return idHumanInitOutput{}, errors.New("issued human certificate is malformed")
	}
	signed, ok := certificates[len(certificates)-1].(map[string]any)
	if !ok {
		return idHumanInitOutput{}, errors.New("issued human certificate is malformed")
	}
	leaf, ok := signed["certificate"].(map[string]any)
	if !ok || leaf == nil {
		return idHumanInitOutput{}, errors.New("issued human certificate is malformed")
	}
	record := human.record
	if record.State == awconfig.HumanRegistered {
		installed, err := proof.Canonical(human.chain)
		if err != nil {
			return idHumanInitOutput{}, err
		}
		incoming, err := proof.Canonical(chain)
		if err != nil {
			return idHumanInitOutput{}, err
		}
		if !bytes.Equal(installed, incoming) {
			return idHumanInitOutput{}, usageError("your human ID already has another certificate; register does not replace it")
		}
		return idHumanInitOutput{Status: "registered", ID: record.StableID, DIDKey: record.DIDKey, Domain: record.Domain, RegistryURL: record.RegistryURL, RegisteredAt: record.RegisteredAt}, nil
	}
	resolver := &awid.NetTXTResolver{}
	authority, err := awid.DiscoverAuthoritativeRegistry(ctx, resolver, record.Domain)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	registryURL, err := domainRegistryURL(authority, strings.TrimSpace(firstNonEmpty(override, record.RegistryURL)))
	if err != nil {
		return idHumanInitOutput{}, err
	}
	registry := newAWIDRegistryClient(nil, resolver)
	registry.DefaultRegistryURL = registryURL
	// Authenticate the issuer before asking the person to sign or making any
	// registration write. A pending global leaf is allowed at this boundary;
	// full committed-chain verification still follows registration below.
	subject := awid.IDChainSubject{ID: record.StableID, DIDKey: record.DIDKey}
	expected := map[string]any{"id": record.StableID, "domain": record.Domain, "kind": "human", "parent": leaf["parent"]}
	before := idStatusAt(registry, resolver, registryURL).IDChainEvidence(ctx, chain, subject, record.Domain)
	if _, err := awid.ImportIDCertificateChain(expected, chain, before, record.Domain); err != nil {
		return idHumanInitOutput{}, fmt.Errorf("issued human certificate issuer refused before registration: %w", err)
	}
	signer := func(description string) awid.IDCertificateSigner {
		return func(payload []byte) (string, []byte, error) { return human.sign(payload, description) }
	}
	if err := registerHumanDID(ctx, human, registry, registryURL); err != nil {
		return idHumanInitOutput{}, err
	}
	receipt, err := registry.RegisterIDCertificateAt(ctx, registryURL, chain, signer("register your issued human certificate at "+registryURL), nil, nil)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	evidence := idStatusAt(registry, resolver, registryURL).IDChainEvidence(ctx, chain, awid.IDChainSubject{ID: record.StableID, DIDKey: record.DIDKey}, record.Domain)
	checked := awid.VerifyIDChain(chain, awid.IDChainSubject{ID: record.StableID, DIDKey: record.DIDKey}, evidence, record.Domain)
	if checked.IdentityValid == nil || !*checked.IdentityValid || checked.Kind == nil || *checked.Kind != "human" {
		return idHumanInitOutput{}, fmt.Errorf("registered human status could not be checked: %s; run register again", checked.Reason)
	}
	if err := awconfig.SaveInstalledIDChain(human.dir, chain); err != nil {
		return idHumanInitOutput{}, err
	}
	record.State = awconfig.HumanRegistered
	record.RegisteredAt, _ = receipt["registered_at"].(string)
	if err := awconfig.SaveHumanRecord(record); err != nil {
		return idHumanInitOutput{}, err
	}
	human.chain = chain
	return idHumanInitOutput{Status: "registered", ID: record.StableID, DIDKey: record.DIDKey, Domain: record.Domain, RegistryURL: registryURL, RegisteredAt: record.RegisteredAt}, nil
}

// Publishing a prepared person's key mapping is separate from issuing or
// registering its ID certificate. Enrollment may need the mapping first.
func registerHumanDID(ctx context.Context, human *humanParticipation, registry *awid.RegistryClient, registryURL string) error {
	record := human.record
	if record.State == awconfig.HumanRegistered {
		return nil
	}
	err := registry.RegisterIdentitySigned(ctx, registryURL, record.DIDKey, record.StableID, func(payload []byte) (string, []byte, error) {
		return human.sign(payload, "register your human key mapping at "+registryURL)
	})
	var already *awid.AlreadyRegisteredError
	if errors.As(err, &already) && already.ExistingDIDKey == record.DIDKey {
		err = nil
	}
	if err != nil {
		return err
	}
	record.State, record.RegistryURL = awconfig.HumanDIDRegistered, registryURL
	return awconfig.SaveHumanRecord(record)
}
