package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var idProofMessageFile, idProofOut string
var idProofCmd = &cobra.Command{
	Use: "proof", Short: "Export a message signed by your human key with its saved evidence",
	Long: `Sign the text in --message-file with your human key at a terminal, asking for
its keychain passphrase once for this command and wiping the key at exit.
The JSON export carries your ID chain and any saved
enrollment evidence. It needs no team or mail server. Missing enrollment is not
a refusal and adds no evidence. Run with --human ID --human-domain DOMAIN.
Saved evidence rides only in proof files; ordinary mail does not yet carry it.

Next: give the output file to anyone. On another machine they run:
  aw verify FILE
No identity, credentials, initialization or registry flag is needed.`,
	Args: cobra.NoArgs, Annotations: map[string]string{humanCommandAnnotation: "registered"},
	RunE: runIDProof,
}

func init() {
	idProofCmd.Flags().StringVar(&idProofMessageFile, "message-file", "", "Text file to sign as your message")
	idProofCmd.Flags().StringVar(&idProofOut, "out", "", "New export file; default is JSON on stdout")
	_ = idProofCmd.MarkFlagRequired("message-file")
	identityCmd.AddCommand(idProofCmd)
}

func runIDProof(cmd *cobra.Command, args []string) error {
	body, err := readFileBounded(idProofMessageFile, maxResponseBytes)
	if err != nil {
		return err
	}
	h := activeHuman
	h.operation = "export your message proof"
	messageID, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	envelope := &awid.MessageEnvelope{FromDID: h.record.DIDKey, FromStableID: h.record.StableID,
		To: h.record.StableID, ToStableID: h.record.StableID, ToDID: h.record.DIDKey,
		Type: "mail", Subject: "Public identity proof", Body: string(body), Timestamp: time.Now().UTC().Format(time.RFC3339), MessageID: messageID}
	payload := awid.CanonicalJSON(envelope)
	sum := sha256.Sum256(body)
	did, signature, err := h.sign([]byte(payload), fmt.Sprintf("export your message (%d bytes, sha256 %x) for anyone to verify", len(body), sum))
	if err != nil {
		return err
	}
	signatureB64 := base64.RawStdEncoding.EncodeToString(signature)
	checked, err := awid.VerifySignedPayload(payload, signatureB64, h.record.DIDKey, did)
	if err != nil || checked != awid.Verified {
		return fmt.Errorf("your keychain signature did not match the selected human key")
	}
	export := messageExport{V: 1, Type: "aweb.message-envelope", SignedPayload: payload, Signature: signatureB64, SigningKeyID: did, IDChain: h.chain}
	evidence, err := readFileBounded(filepath.Join(h.dir, "approval-evidence.json"), maxResponseBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if !json.Valid(evidence) {
			return fmt.Errorf("saved approval evidence is not JSON")
		}
		export.Evidence = evidence
	}
	raw, err := json.Marshal(export)
	if err != nil {
		return err
	}
	if err := writeExchangeFile(idProofOut, raw); err != nil {
		return err
	}
	if idProofOut != "" && idProofOut != "-" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Give %s to the recipient; they run aw verify %s on their machine.\n", idProofOut, idProofOut)
	}
	return nil
}
