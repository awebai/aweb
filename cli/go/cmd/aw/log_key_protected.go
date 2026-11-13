package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

var logKeyProtectedProfile, logKeyApprover string

func logProtectedProfile() (*handoff.Profile, error) {
	raw, err := os.ReadFile(strings.TrimSpace(logKeyProtectedProfile))
	if err != nil {
		return nil, err
	}
	return handoff.ParseProfile(raw)
}

// protectedLogIntent validates the public record and projects only the four
// approved subject fields. The current controller pin comes from the profile.
func protectedLogIntent(profile *handoff.Profile, binding *handoff.ProfileBinding, rec *awid.LogKeyRecord) (map[string]any, error) {
	if rec == nil || rec.V != 1 {
		return nil, usageError("a version 1 public log key record is required")
	}
	authority, _ := binding.Scope["authority"].(map[string]any)
	if authority["kind"] != "team_controller" || authority["id"] != rec.TeamID {
		return nil, usageError("the record team must match the protected controller scope")
	}
	instant, err := time.Parse("2006-01-02T15:04:05Z", rec.CreatedAt)
	if err != nil || instant.UTC().Format("2006-01-02T15:04:05Z") != rec.CreatedAt {
		return nil, usageError("created_at must be canonical UTC seconds")
	}
	public, publicErr := base64.RawStdEncoding.Strict().DecodeString(rec.PublicKey)
	if publicErr != nil || len(public) != 32 || base64.RawStdEncoding.EncodeToString(public) != rec.PublicKey {
		return nil, usageError("public_key must be canonical unpadded standard base64 of 32 bytes")
	}
	candidate := *rec
	candidate.TeamKeyDID = binding.AuthorityKeyDID
	if _, err := awid.LogKeyRecordSigningBytes(&candidate); err != nil {
		return nil, err
	}
	return protectedRoleIntent("team.log-key.sign", binding.Scope, profile.RequestOrigin, map[string]any{"team_id": rec.TeamID, "key_id": rec.KeyID, "public_key": rec.PublicKey, "created_at": rec.CreatedAt}), nil
}

// protectedLogRecord accepts only the actual producer receipt, exactly matching
// the requested record and pinned controller. No response field selects a key.
func protectedLogRecord(rec *awid.LogKeyRecord, did string, result json.RawMessage) (*awid.LogKeyRecord, error) {
	invalid := withErrorCode("signed_record_invalid", errors.New("the committed receipt does not sign the requested log key record"))
	fields, ok := handoff.DecodeObject(result)
	if !ok || len(fields) != 2 {
		return nil, invalid
	}
	signingText, ok := fields["signing"].(string)
	if !ok {
		return nil, invalid
	}
	signatureText, ok := fields["signature"].(string)
	if !ok {
		return nil, invalid
	}
	signing, err := base64.StdEncoding.Strict().DecodeString(signingText)
	if err != nil || base64.StdEncoding.EncodeToString(signing) != signingText {
		return nil, invalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signature) != 64 || base64.StdEncoding.EncodeToString(signature) != signatureText {
		return nil, invalid
	}
	candidate := *rec
	candidate.TeamKeyDID = did
	candidate.Signature = ""
	expected, err := awid.LogKeyRecordSigningBytes(&candidate)
	if err != nil || !bytes.Equal(signing, expected) {
		return nil, invalid
	}
	if err := awid.AttachLogKeyRecordSignature(&candidate, did, base64.RawStdEncoding.EncodeToString(signature)); err != nil {
		return nil, invalid
	}
	return &candidate, nil
}

func settleProtectedLog(cmd *cobra.Command, id string, rec *awid.LogKeyRecord, did string, receipt *handoff.Receipt, operationErr error, out string) error {
	if operationErr != nil {
		if receipt != nil && receipt.State == "refused" {
			if err := awconfig.RemovePendingGovernanceOperation(id); err != nil {
				return err
			}
		}
		return withErrorCode(handoff.ErrorCode(operationErr), fmt.Errorf("operation %s: %w; its saved request can be resumed", id, operationErr))
	}
	if receipt == nil || receipt.State != "committed" || receipt.OperationID != id {
		return withErrorCode("receipt_unavailable", errors.New("no matching committed log key receipt; request retained"))
	}
	signed, err := protectedLogRecord(rec, did, receipt.Result)
	if err != nil {
		return err
	}
	if err := writeLogKeyRecord(cmd, signed, out, "Signed log key record %s for team %s written to %s; install it on each agent host.\n"); err != nil {
		return err
	}
	return awconfig.RemovePendingGovernanceOperation(id)
}

func runProtectedLogSign(cmd *cobra.Command) error {
	if logKeySignOffline || logKeySignTeamKeyDID != "" || logKeySignSignature != "" {
		return usageError("choose only --protected-profile with --approver, or one explicit external/offline route")
	}
	profile, err := logProtectedProfile()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(logKeySignRecord)
	if err != nil {
		return err
	}
	fields, ok := handoff.DecodeObject(raw)
	if !ok || len(fields) != 7 {
		return usageError("the public log key record must have exactly its seven fields")
	}
	for _, name := range []string{"v", "team_id", "key_id", "public_key", "created_at", "team_key_did", "signature"} {
		if _, ok := fields[name]; !ok {
			return usageError("the public log key record is incomplete")
		}
	}
	var rec awid.LogKeyRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	binding, err := protectedBinding(profile, rec.TeamID, strings.TrimSpace(logKeyApprover))
	if err != nil {
		return err
	}
	intent, err := protectedLogIntent(profile, binding, &rec)
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	id, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	opts := governanceOptions(cmd, profile, binding.Scope, identity)
	opts.Forget = nil
	receipt, err := handoff.Approve(cmd.Context(), opts, id, intent)
	return settleProtectedLog(cmd, id, &rec, binding.AuthorityKeyDID, receipt, err, logKeySignOut)
}

// Resume materializes the record from the retained request, never a replacement
// input file. The shared Resume path verifies the same request digest again.
var teamLogKeyResumeCmd = &cobra.Command{
	Use: "resume <operation-id>", Short: "Resume protected log key signing from its saved request", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profile, err := logProtectedProfile()
		if err != nil {
			return err
		}
		saved, err := pendingOperationFor(profile, args[0])
		if err != nil {
			return err
		}
		fields, ok := handoff.DecodeObject(saved.Body)
		if !ok || fields["operation"] != "team.log-key.sign" || fields["variant"] != "default" || fields["audience"] != profile.RequestOrigin || fields["operation_id"] != args[0] {
			return usageError("saved request is not this protected log key operation")
		}
		scope, err := savedScope(profile, saved.Body)
		if err != nil {
			return err
		}
		binding, err := profile.BindingFor(scope)
		if err != nil {
			return err
		}
		subject, ok := fields["subject"].(map[string]any)
		if !ok || len(subject) != 4 {
			return usageError("invalid saved log key subject")
		}
		text, err := json.Marshal(subject)
		if err != nil {
			return err
		}
		rec := awid.LogKeyRecord{V: 1}
		if err = json.Unmarshal(text, &rec); err != nil {
			return err
		}
		if _, err := protectedLogIntent(profile, binding, &rec); err != nil {
			return err
		}
		identity, err := resolveLocalSigningIdentity()
		if err != nil {
			return err
		}
		opts := governanceOptions(cmd, profile, scope, identity)
		opts.Forget = nil
		receipt, err := handoff.Resume(cmd.Context(), opts, saved.Body)
		return settleProtectedLog(cmd, args[0], &rec, binding.AuthorityKeyDID, receipt, err, logKeySignOut)
	},
}

func init() {
	teamLogKeySignCmd.Flags().StringVar(&logKeyProtectedProfile, "protected-profile", "", "Public operator profile for protected live approval")
	teamLogKeySignCmd.Flags().StringVar(&logKeyApprover, "approver", "", "The did:aw of the configured approving human")
	teamLogKeyResumeCmd.Flags().StringVar(&logKeyProtectedProfile, "protected-profile", "", "The original protected service profile")
	teamLogKeyResumeCmd.Flags().StringVar(&logKeySignOut, "out", "", "Write the signed public record to this file instead of stdout")
	teamLogKeyCmd.AddCommand(teamLogKeyResumeCmd)
}
