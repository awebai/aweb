package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/approval"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// messageExport carries original signed bytes and the adjacent ID presentation.
// No server projection or previous verification result is an input to verification.
type messageExport struct {
	V                 int                       `json:"v"`
	Type              string                    `json:"type"`
	SignedPayload     string                    `json:"signed_payload,omitempty"`
	Signature         string                    `json:"signature,omitempty"`
	SigningKeyID      string                    `json:"signing_key_id,omitempty"`
	EncryptedEnvelope *awid.E2EEMessageEnvelope `json:"encrypted_envelope,omitempty"`
	IDChain           awid.ReceivedIDChain      `json:"id_chain,omitempty"`
	// Reserve versioned evidence without trusting or interpreting its contents.
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

var verifyRegistry string

var verifyCmd = &cobra.Command{
	Use:   "verify [FILE|-]",
	Short: "Verify an exported message and its responsible human without credentials",
	Long: `Verify an exported signed message using only its original signed content,
DNS and public registry reads. No identity, team, token or initialization is needed.
FILE defaults to stdin; - also reads stdin. Export with:
  aw mail show --message-id ID --envelope > message.json

Print the same responsibility result as aw who, with invalid proof shown explicitly
as invalid. --json retains the shared outcome and identity_valid fields: invalid
proof has outcome unknown and identity_valid false. Lookup failures are unavailable,
never valid. A verified signature alone does not establish a responsible human.
Encrypted exports can be verified without decrypting their content.
Exit 0 for valid or normal unknown results, 1 for invalid proof, 2 for unavailable
evidence or unreadable input.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyRegistry, "registry", "", "Registry origin, when the domain's _awid record names none (same restriction as aw who)")
	verifyCmd.GroupID = groupIdentity
	rootCmd.AddCommand(verifyCmd)
	identityHomeNeutralCommandExemptions[verifyCmd] = struct{}{}
	offlineCommands[verifyCmd] = struct{}{}
}

func runVerify(cmd *cobra.Command, args []string) error {
	input := cmd.InOrStdin()
	if len(args) == 1 && args[0] != "-" {
		file, err := os.Open(args[0])
		if err != nil {
			return usageError("read envelope: %v", err)
		}
		defer file.Close()
		input = file
	}
	raw, err := awid.ReadAllBounded(input, awid.MaxResponseSize)
	if err != nil {
		return usageError("read envelope: %v", err)
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	out := verifyExportedMessage(ctx, raw, whoOptions{RegistryURL: verifyRegistry, TXTResolver: &awid.NetTXTResolver{}})
	printOutput(out, formatVerifiedMessage)
	if out.IdentityValid != nil && !*out.IdentityValid {
		return &cliError{code: 1, msg: "invalid message proof: " + out.Reason}
	}
	if out.Outcome == "unavailable" {
		return &cliError{code: 2, msg: "message proof unavailable: " + out.Reason}
	}
	return nil
}

func messageVerificationFailure(id, reason string, invalid bool) whoOutput {
	result := awid.IDChainResult{Outcome: "unavailable", Reason: reason}
	if invalid {
		no := false
		result.Outcome = "unknown"
		result.IdentityValid = &no
	}
	return whoOutput{ID: id, IDChainResult: result}
}

func verifyExportedMessage(ctx context.Context, raw []byte, opts whoOptions) (out whoOutput) {
	var export messageExport
	defer func() {
		out.Evidence = exportEvidenceReports(ctx, export.Evidence, export.IDChain, out, opts.EvidenceTrust)
	}()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&export); err != nil {
		return messageVerificationFailure("", "malformed_envelope", true)
	}
	if decoder.Decode(new(any)) != io.EOF || export.V != 1 || export.Type != "aweb.message-envelope" || !uniqueExportMembers(raw) {
		return messageVerificationFailure("", "malformed_envelope", true)
	}
	message := awid.InboxMessage{IDChain: export.IDChain}
	address := ""
	if encrypted := export.EncryptedEnvelope; encrypted != nil {
		if export.SignedPayload != "" || export.Signature != "" || export.SigningKeyID != "" {
			return messageVerificationFailure("", "malformed_envelope", true)
		}
		if awid.VerifyE2EEMessageEnvelopeSignature(encrypted) != nil {
			return messageVerificationFailure("", "message_signature_invalid", true)
		}
		message.FromDID, message.FromStableID = encrypted.From.DID, encrypted.From.StableID
		address = encrypted.From.Address
		message.ContentMode = awid.ContentModeEncryptedV2
	} else {
		var signed awid.MessageEnvelope
		if json.Unmarshal([]byte(export.SignedPayload), &signed) != nil {
			return messageVerificationFailure("", "malformed_envelope", true)
		}
		status, err := awid.VerifySignedPayload(export.SignedPayload, export.Signature, signed.FromDID, export.SigningKeyID)
		if err != nil || status != awid.Verified {
			return messageVerificationFailure("", "message_signature_invalid", true)
		}
		message.FromDID, message.FromStableID = signed.FromDID, signed.FromStableID
		message.SignedPayload = export.SignedPayload
		address = signed.From
	}
	message.VerificationStatus = awid.Verified
	subject := awid.IDChainSubject{ID: message.FromStableID, DIDKey: message.FromDID}
	if subject.ID == "" {
		subject.ID = subject.DIDKey
	}
	if !strings.HasPrefix(subject.ID, "did:aw:") && subject.ID != subject.DIDKey {
		return messageVerificationFailure(subject.ID, "subject_mismatch", true)
	}
	// Reject structurally invalid presentations before any DNS/registry lookup.
	preflight := awid.VerifyIDChain(export.IDChain, subject, nil, "")
	if preflight.Reason != "evidence_unavailable" {
		return whoOutput{ID: subject.ID, IDChainResult: preflight}
	}
	registry := newAWIDRegistryClient(nil, opts.TXTResolver)
	status := awid.NewIDStatusClient(registry, opts.TXTResolver)
	override := opts.RegistryURL
	// Select every domain's registry under the same rule as who. Keeping route
	// failures inside the shared status client makes DNS outages unavailable too.
	status.Route = func(ctx context.Context, domain string) (string, error) {
		authority, err := awid.DiscoverAuthoritativeRegistry(ctx, opts.TXTResolver, domain)
		if err != nil {
			return "", err
		}
		return domainRegistryURL(authority, override)
	}
	if strings.HasPrefix(subject.ID, "did:aw:") {
		// An addressless proof supplies its domain through the certificate.
		// DNS selects the registry; only its coherent key response names enrollment.
		registryURL := strings.TrimSpace(opts.RegistryURL)
		domain, err := exportedMessageKeyDomain(address, export.IDChain, subject)
		if err != nil {
			return messageVerificationFailure(subject.ID, "malformed_envelope", true)
		}
		if domain != "" {
			var err error
			registryURL, err = status.Route(ctx, domain)
			if err != nil {
				return messageVerificationFailure(subject.ID, "evidence_unavailable", false)
			}
		}
		if registryURL == "" {
			registryURL = registry.DefaultRegistryURL
		}
		key, err := registry.ResolveKeyAt(ctx, registryURL, subject.ID)
		if err != nil {
			return messageVerificationFailure(subject.ID, "evidence_unavailable", false)
		}
		entries, err := registry.GetDIDLog(ctx, registryURL, subject.ID)
		if err != nil {
			return messageVerificationFailure(subject.ID, "evidence_unavailable", false)
		}
		head, err := awid.VerifyDidLogEntries(subject.ID, entries, time.Now())
		if err != nil || head == nil || key.DIDAW != subject.ID || head.CurrentDIDKey != key.CurrentDIDKey || key.CurrentDIDKey != subject.DIDKey {
			return messageVerificationFailure(subject.ID, "subject_mismatch", true)
		}
		enrollment := key.IDTreeEnrollmentOf(subject.ID, subject.DIDKey, time.Now())
		opts.ReceivedEnrollment = func(context.Context, string, string) awid.IDTreeEnrollmentResult { return enrollment }
	}
	opts.Status = status
	if opts.EvidenceTrust == nil {
		opts.EvidenceTrust = func(ctx context.Context, chain []any, person, key, domain string) (*proof.Trust, error) {
			checked, err := proof.ReadTrust(ctx, status, chain, person, key, domain)
			if err != nil {
				return nil, err
			}
			return &checked, nil
		}
	}
	opts.RegistryURL = "" // The route above already enforces the explicit override.
	out, err := executeWhoReceived(ctx, message, opts)
	if err != nil {
		return messageVerificationFailure(subject.ID, "evidence_unavailable", false)
	}
	return out
}

// Preserve signed-address discovery for messages. Addressless proof exports
// discover through the presented certificate's domain, which the shared chain
// checks require to be the same on every link. This is a DNS lookup hint, never
// a registry URL or a trust anchor supplied by the export.
func exportedMessageKeyDomain(address string, chain awid.ReceivedIDChain, subject awid.IDChainSubject) (string, error) {
	if domain, _, ok := strings.Cut(address, "/"); ok && domain != "" {
		return domain, nil
	}
	if chain == nil {
		return "", nil
	}
	plan, err := awid.IDStatusRequest(chain, subject, "")
	if err != nil {
		return "", err
	}
	domain, _ := plan["domain"].(string)
	return domain, nil
}

// Check original outer names before trusting encoding/json's last-wins result.
// Values stay opaque, including evidence and the original signed payload.
// Strict field decoding runs first, so unique names are limited to known fields.
func uniqueExportMembers(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	var names []string
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return false
		}
		for _, seen := range names {
			// Match the typed decoder's case-insensitive field aliases too.
			if strings.EqualFold(seen, name) {
				return false
			}
		}
		names = append(names, name)
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}')
}

func formatVerifiedMessage(v any) string {
	out := v.(whoOutput)
	if out.IdentityValid != nil && !*out.IdentityValid {
		return fmt.Sprintf("%s\nHuman: invalid (%s)\n", out.ID, out.Reason)
	}
	text := formatWho(out)
	for _, report := range out.Evidence {
		text += approval.FormatEvidence(report) + "\n"
	}
	return text
}

func exportMailEnvelope(messages []awid.InboxMessage, messageID string) (messageExport, error) {
	if len(messages) != 1 || messages[0].MessageID != messageID {
		return messageExport{}, fmt.Errorf("expected one exact message matching --message-id")
	}
	message := messages[0]
	export := messageExport{V: 1, Type: "aweb.message-envelope", IDChain: message.IDChain}
	if message.Encrypted != nil {
		export.EncryptedEnvelope = message.Encrypted
	} else {
		if message.SignedPayload == "" || message.Signature == "" {
			return messageExport{}, fmt.Errorf("message has no original signed envelope to export")
		}
		export.SignedPayload, export.Signature, export.SigningKeyID = message.SignedPayload, message.Signature, message.SigningKeyID
	}
	return export, nil
}
