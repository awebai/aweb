package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const (
	doctorCheckMessagingMailSignature = "messaging.local.mail_signature_dry_run"
	doctorCheckMessagingChatSignature = "messaging.local.chat_signature_dry_run"
	doctorCheckMessagingInboxRead     = "messaging.server.inbox_read"
	doctorCheckMessagingChatPending   = "messaging.server.chat_pending_read"
	doctorCheckMessagingChatSessions  = "messaging.server.chat_sessions_read"
	doctorCheckMessagingContactsRead  = "messaging.server.contacts_read"
	doctorCheckMessagingPolicyRead    = "messaging.server.policy_read"
)

type doctorMessagingState struct {
	awebState *doctorAwebState

	did      string
	stableID string
	address  string
	lifetime string

	signingKey ed25519.PrivateKey
	signingErr error
}

type doctorContactsResponse struct {
	Contacts []struct {
		ContactID      string `json:"contact_id"`
		ContactAddress string `json:"contact_address"`
		Label          string `json:"label"`
		CreatedAt      string `json:"created_at"`
	} `json:"contacts"`
}

func (r *doctorRunner) runMessagingDoctorChecks() {
	state := collectDoctorMessagingState(r.workingDir)
	r.addMessagingLocalSignatureChecks(state)
	networkIDs := []string{
		doctorCheckMessagingInboxRead,
		doctorCheckMessagingChatPending,
		doctorCheckMessagingChatSessions,
		doctorCheckMessagingContactsRead,
		doctorCheckMessagingPolicyRead,
	}
	if state.awebState != nil && state.awebState.hasNoWorkspaceContext() {
		r.addNoContextAwebChecks(networkIDs, "no_workspace_context")
		return
	}
	if r.opts.Mode != doctorModeOnline {
		r.addSkippedAwebChecks(networkIDs)
		return
	}
	client, prereq := r.doctorMessagingClient(state)
	if prereq != "" {
		r.addBlockedAwebChecks(networkIDs, prereq)
		return
	}
	r.addMessagingOnlineChecks(client)
}

func collectDoctorMessagingState(workingDir string) *doctorMessagingState {
	awebState := collectDoctorAwebState(workingDir)
	state := &doctorMessagingState{
		awebState:  awebState,
		signingKey: awebState.signingKey,
		signingErr: awebState.signingKeyErr,
	}
	identityState := collectDoctorIdentityState(workingDir)
	state.did = strings.TrimSpace(identityState.did)
	state.stableID = strings.TrimSpace(identityState.stableID)
	state.address = strings.TrimSpace(identityState.address)
	state.lifetime = strings.TrimSpace(identityState.lifetime)
	if state.signingKey == nil {
		state.signingKey = identityState.signingKey
		state.signingErr = identityState.signingKeyErr
	}
	return state
}

func (r *doctorRunner) addMessagingLocalSignatureChecks(state *doctorMessagingState) {
	if state.signingErr != nil || state.signingKey == nil {
		status := doctorStatusFail
		reason := safeLocalKeyError(state.signingErr)
		if errors.Is(state.signingErr, os.ErrNotExist) {
			reason = "missing"
		}
		if state.awebState != nil && state.awebState.hasNoWorkspaceContext() {
			status = doctorStatusInfo
			reason = "no_workspace_context"
		}
		detail := map[string]any{"reason": reason}
		r.add(awebCheck(doctorCheckMessagingMailSignature, status, localPathTarget(awconfig.WorktreeSigningKeyPath(r.workingDir)), "Mail signature dry-run requires a local signing key.", "Restore .aw/signing.key before using signed messaging.", detail))
		r.add(awebCheck(doctorCheckMessagingChatSignature, status, localPathTarget(awconfig.WorktreeSigningKeyPath(r.workingDir)), "Chat signature dry-run requires a local signing key.", "Restore .aw/signing.key before using signed messaging.", detail))
		return
	}
	did := strings.TrimSpace(state.did)
	if did == "" {
		did = awid.ComputeDIDKey(state.signingKey.Public().(ed25519.PublicKey))
	}
	if awid.ComputeDIDKey(state.signingKey.Public().(ed25519.PublicKey)) != did {
		r.add(awebCheck(doctorCheckMessagingMailSignature, doctorStatusBlocked, &doctorTarget{Type: "did", ID: did}, "Mail signature dry-run is blocked by local DID/signing-key mismatch.", "Resolve identity.local.signing_key_matches_did first.", map[string]any{"prerequisite": doctorCheckIdentityLocalSigningKey}))
		r.add(awebCheck(doctorCheckMessagingChatSignature, doctorStatusBlocked, &doctorTarget{Type: "did", ID: did}, "Chat signature dry-run is blocked by local DID/signing-key mismatch.", "Resolve identity.local.signing_key_matches_did first.", map[string]any{"prerequisite": doctorCheckIdentityLocalSigningKey}))
		return
	}
	r.addMessagingSignatureCheck(doctorCheckMessagingMailSignature, "mail", state, did)
	r.addMessagingSignatureCheck(doctorCheckMessagingChatSignature, "chat", state, did)
}

func (r *doctorRunner) addMessagingSignatureCheck(id, messageType string, state *doctorMessagingState, did string) {
	env := &awid.MessageEnvelope{
		From:         strings.TrimSpace(state.address),
		FromDID:      did,
		FromStableID: strings.TrimSpace(state.stableID),
		To:           strings.TrimSpace(state.address),
		Type:         messageType,
		Subject:      "",
		Body:         "doctor-check",
		Timestamp:    "2026-04-18T00:00:00Z",
		MessageID:    "doctor-dry-run",
		SigningKeyID: did,
	}
	if messageType == "mail" {
		env.Subject = "doctor"
	}
	signature, err := awid.SignMessage(state.signingKey, env)
	if err != nil {
		r.add(awebCheck(id, doctorStatusFail, &doctorTarget{Type: "did", ID: did}, "Local messaging signature dry-run failed.", "Repair local signing key state before using messaging.", map[string]any{"reason": "sign_failed", "type": messageType}))
		return
	}
	env.Signature = signature
	status, err := awid.VerifyMessage(env)
	if err != nil || status != awid.Verified {
		r.add(awebCheck(id, doctorStatusFail, &doctorTarget{Type: "did", ID: did}, "Local messaging signature dry-run did not verify.", "Repair local signing key state before using messaging.", map[string]any{"reason": "verify_failed", "type": messageType, "verification_status": string(status)}))
		return
	}
	r.add(awebCheck(id, doctorStatusOK, &doctorTarget{Type: "did", ID: did}, "Local messaging signature dry-run signs and verifies in memory.", "", map[string]any{"type": messageType, "did_key": did, "secret_values_emitted": false}))
}

func (r *doctorRunner) doctorMessagingClient(state *doctorMessagingState) (*aweb.Client, string) {
	if state == nil || state.awebState == nil {
		return nil, doctorCheckWorkspaceParse
	}
	awebState := state.awebState
	if awebState.workspaceErr != nil {
		return nil, doctorCheckWorkspaceParse
	}
	if strings.TrimSpace(awebState.baseURL) == "" || awebState.urlErr != nil {
		return nil, doctorCheckServerAwebURLConfigured
	}
	if state.signingErr != nil || state.signingKey == nil {
		return nil, doctorCheckSigningKeyParse
	}
	did := strings.TrimSpace(state.did)
	if did == "" {
		did = awid.ComputeDIDKey(state.signingKey.Public().(ed25519.PublicKey))
	}
	raw, err := awid.NewWithIdentity(awebState.baseURL, state.signingKey, did)
	if err != nil {
		return nil, doctorCheckMessagingMailSignature
	}
	client := &aweb.Client{Client: raw}
	client.SetAddress(strings.TrimSpace(state.address))
	if strings.TrimSpace(state.stableID) != "" {
		client.SetStableID(strings.TrimSpace(state.stableID))
	}
	return client, ""
}

func (r *doctorRunner) addMessagingOnlineChecks(client *aweb.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if inbox, err := client.Inbox(ctx, awid.InboxParams{Limit: 1}); err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckMessagingInboxRead, err, "Inbox read failed under current identity credentials.", "Retry with the current identity credentials or repair local signing key state.")
	} else {
		r.add(awebCheck(doctorCheckMessagingInboxRead, doctorStatusOK, nil, "Inbox can be read under current identity credentials.", "", map[string]any{"message_count": len(inbox.Messages)}))
	}
	if pending, err := client.ChatPending(ctx); err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckMessagingChatPending, err, "Chat pending read failed under current identity credentials.", "Retry with the current identity credentials or repair local signing key state.")
	} else {
		r.add(awebCheck(doctorCheckMessagingChatPending, doctorStatusOK, nil, "Pending chat state can be read under current identity credentials.", "", map[string]any{"pending_count": len(pending.Pending), "messages_waiting": pending.MessagesWaiting}))
	}
	if sessions, err := client.ChatListSessions(ctx); err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckMessagingChatSessions, err, "Chat sessions read failed under current identity credentials.", "Retry with the current identity credentials or repair local signing key state.")
	} else {
		r.add(awebCheck(doctorCheckMessagingChatSessions, doctorStatusOK, nil, "Chat sessions can be read under current identity credentials.", "", map[string]any{"session_count": len(sessions.Sessions)}))
	}
	var contacts doctorContactsResponse
	if err := client.Get(ctx, "/v1/contacts", &contacts); err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckMessagingContactsRead, err, "Contacts read failed under current identity credentials.", "Retry with the current identity credentials or repair local signing key state.")
	} else {
		r.add(awebCheck(doctorCheckMessagingContactsRead, doctorStatusOK, nil, "Messaging contacts can be read under current identity credentials.", "", map[string]any{"contact_count": len(contacts.Contacts)}))
	}
	r.add(awebCheck(doctorCheckMessagingPolicyRead, doctorStatusUnknown, nil, "Messaging policy readability was not probed because no safe read-only policy endpoint is available.", "Add a dedicated read-only policy endpoint before making this check authoritative.", map[string]any{"reason": "no_read_endpoint"}))
}
