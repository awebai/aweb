package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// A human-role act through an operator-provisioned protected service
// (human-assurance-contract.md sections 3 and 5): this identity prepares the
// exact act as a restricted requester, the controlling human approves it on
// the service's page, and aw reports only the receipt. aw holds no controller
// key and no approval.

var (
	appProtectedProfileFlag string
	appApproverFlag         string
	appRoleReplaceFlag      string
)

var appRoleResumeCmd = &cobra.Command{
	Use:   "resume <operation-id>",
	Short: "Resume a protected role act whose prepare answer was lost, from its saved request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProtectedResume(cmd, args[0])
	},
}

func loadProtectedProfile() (*handoff.Profile, error) {
	home, err := identityHomeForDir("")
	if err != nil {
		return nil, err
	}
	path, err := protectedProfilePath(appProtectedProfileFlag, home.Root)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return handoff.ParseProfile(raw)
}

// protectedBinding is the profile's one binding for exactly this team's
// controller and the named approving human. It never picks a default human,
// and refuses an approver the profile binds more than once.
func protectedBinding(profile *handoff.Profile, teamID, approver string) (*handoff.ProfileBinding, error) {
	if strings.TrimSpace(approver) == "" {
		return nil, usageError("--approver is required: the did:aw of the human who approves this act")
	}
	domain, _, err := awid.ParseTeamID(teamID)
	if err != nil {
		return nil, err
	}
	var matches []*handoff.ProfileBinding
	for i := range profile.Bindings {
		scope := profile.Bindings[i].Scope
		authority, _ := scope["authority"].(map[string]any)
		human, _ := scope["human"].(map[string]any)
		if authority["kind"] == "team_controller" && authority["id"] == teamID && authority["domain"] == domain && human["id"] == approver {
			matches = append(matches, &profile.Bindings[i])
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, withErrorCode("profile_scope_refused", fmt.Errorf("the protected-service profile configures no binding for team %s approved by %s", teamID, approver))
	}
	// The same approver bound in more than one human domain: the profile's
	// row order must not choose whose scope is signed.
	return nil, withErrorCode("profile_scope_ambiguous", fmt.Errorf("the protected-service profile binds %s for team %s in %d human domains; it must name one", approver, teamID, len(matches)))
}

// protectedRoleIntent is the act aw asks the service to prepare.
func protectedRoleIntent(act string, scope map[string]any, audience string, subject map[string]any) map[string]any {
	return map[string]any{"operation": act, "variant": "default", "approval_format": "intent_v1", "scope": scope, "audience": audience, "subject": subject}
}

// protectedRequesterSigner sends requests to the profile's request origin as
// this identity, proving it with a freshly timestamped covering-v2 envelope
// over scope. Redirects are never followed.
func protectedRequesterSigner(profile *handoff.Profile, scope map[string]any, identity *localSigningIdentity) handoff.Signer {
	return func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
		headers, err := handoff.ProtectedRequestHeaders(handoff.ProtectedRequest{
			Profile: profile, Scope: scope, RequesterID: identity.StableID,
			Method: method, Path: target.RequestURI(), Body: body,
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Sign:      handoff.RequestKeySigner(awid.KeySigner(identity.SigningKey)),
		})
		if err != nil {
			return nil, err
		}
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
		if err != nil {
			return nil, err
		}
		req.Header = headers
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return awid.DoNoRedirectWithTimeout(http.DefaultClient, req, awid.APITimeout())
	}
}

// governanceOptions are the options of one protected operation: the
// profile's pinned origins, this identity as requester, and its request kept
// in aw's owner-only state until a final receipt.
func governanceOptions(cmd *cobra.Command, profile *handoff.Profile, scope map[string]any, identity *localSigningIdentity) handoff.GovernanceOptions {
	return handoff.GovernanceOptions{
		Request: profile.RequestOrigin, Human: profile.HumanOrigin,
		Sign: protectedRequesterSigner(profile, scope, identity), Open: openBrowser, Notify: cmd.ErrOrStderr(),
		Save: func(operationID string, body []byte) error {
			return awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{
				OperationID: operationID, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: body,
			})
		},
		// The saved request is removed by the command once its committed
		// result verifies, not on any committed receipt: a result not yet
		// verified, or an act whose application is not confirmed, stays
		// resumable.
	}
}

// runProtectedHumanRoleAct prepares act through the protected service named
// by --protected-profile and waits for its receipt.
func runProtectedHumanRoleAct(cmd *cobra.Command, act, teamID string, audience string, subject map[string]any) error {
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	binding, err := protectedBinding(profile, teamID, strings.TrimSpace(appApproverFlag))
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s for %s on %s, approved by %s through %s\n", act, subject["principal"], subject["app_id"], appApproverFlag, profile.ServiceID)
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	return requestProtectedRoleAct(ctx, cmd, profile, binding, requesterOptions(cmd, profile, identity), act, audience, subject, strings.TrimSpace(appRoleReplaceFlag))
}

// requesterOptions are the governance options of a protected operation under
// scope, with this identity as requester, and false when the profile no
// longer binds that scope.
func requesterOptions(cmd *cobra.Command, profile *handoff.Profile, identity *localSigningIdentity) func(map[string]any) (handoff.GovernanceOptions, bool) {
	return func(scope map[string]any) (handoff.GovernanceOptions, bool) {
		if _, err := profile.BindingFor(scope); err != nil {
			return handoff.GovernanceOptions{}, false
		}
		return governanceOptions(cmd, profile, scope, identity), true
	}
}

// requestProtectedRoleAct prepares act under binding for the human's
// approval and settles its receipt, after an unfinished earlier request for
// the same act and subject that aw cannot continue has been read and
// settled, or explicitly replaced (guardUnfinished).
func requestProtectedRoleAct(ctx context.Context, cmd *cobra.Command, profile *handoff.Profile, binding *handoff.ProfileBinding,
	optionsFor func(map[string]any) (handoff.GovernanceOptions, bool), act, audience string, subject map[string]any, replace string) error {
	intent := protectedRoleIntent(act, binding.Scope, audience, subject)
	settled, err := guardUnfinished(ctx, cmd.ErrOrStderr(), profile, optionsFor, intent, sameCanonical, replace, roleActReading(profile, time.Now()))
	if err != nil {
		return err
	}
	if settled != nil {
		printSettledRoleAct(settled)
		return nil
	}
	operationID, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	var frozen map[string]any
	opts, _ := optionsFor(binding.Scope)
	opts.CheckPrepared = ownerActCheck(binding.AuthorityKeyDID, &frozen)
	receipt, err := handoff.Approve(ctx, opts, operationID, intent)
	return settleProtectedAct(cmd, operationID, frozen, binding, receipt, err)
}

// printSettledRoleAct reports an earlier request found already applied.
func printSettledRoleAct(report map[string]any) {
	printOutput(report, func(any) string {
		return fmt.Sprintf("The earlier request %s had already committed; %s was applied by the protected service.\n", report["operation_id"], report["act"])
	})
}

// pendingOperationFor is the saved operation operationID, if profile pins the
// same origins it was prepared under.
func pendingOperationFor(profile *handoff.Profile, operationID string) (*awconfig.PendingGovernanceOperation, error) {
	saved, err := awconfig.LoadPendingGovernanceOperation(operationID)
	if err != nil {
		return nil, err
	}
	if saved == nil {
		return nil, usageError("no saved request for operation %s", operationID)
	}
	if saved.RequestOrigin != profile.RequestOrigin || saved.HumanOrigin != profile.HumanOrigin {
		return nil, usageError("operation %s was prepared at request origin %s and human origin %s, not this profile's", operationID, saved.RequestOrigin, saved.HumanOrigin)
	}
	return saved, nil
}

// savedScope is the configured scope a saved request was prepared under.
func savedScope(profile *handoff.Profile, body []byte) (map[string]any, error) {
	// Decoded as strictly as Resume decodes the same bytes.
	fields, ok := handoff.DecodeObject(body)
	scope, _ := fields["scope"].(map[string]any)
	if !ok || scope == nil {
		return nil, errors.New("the saved request names no scope")
	}
	if _, err := profile.BindingFor(scope); err != nil {
		return nil, err
	}
	return scope, nil
}

func runProtectedResume(cmd *cobra.Command, operationID string) error {
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	saved, err := pendingOperationFor(profile, operationID)
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	return resumeProtectedRoleAct(ctx, cmd, profile, saved, requesterOptions(cmd, profile, identity))
}

// resumeProtectedRoleAct continues saved from its exact bytes. A saved
// request aw cannot continue (quarantined, in another approval format, or
// under a binding the profile no longer has) is never sent again: its
// receipt is read once, and it is settled when that answer is definite.
func resumeProtectedRoleAct(ctx context.Context, cmd *cobra.Command, profile *handoff.Profile, saved *awconfig.PendingGovernanceOperation,
	optionsFor func(map[string]any) (handoff.GovernanceOptions, bool)) error {
	scope, err := savedScope(profile, saved.Body)
	body, _ := handoff.DecodeObject(saved.Body)
	if err != nil || saved.Quarantine != nil || body["approval_format"] != "intent_v1" {
		report, refused, err := reconcileUnfinished(ctx, optionsFor, saved, roleActReading(profile, time.Now()))
		switch {
		case err != nil:
			return err
		case refused:
			return withErrorCode("earlier_operation_refused", fmt.Errorf("operation %s was refused, so it took no effect", saved.OperationID))
		case report != nil:
			printSettledRoleAct(report)
			return nil
		}
		return withErrorCode("operation_reconciliation_required", fmt.Errorf(
			"operation %s cannot be continued by this aw and may still have taken effect: %s; check the current state, and to ask for a separately approved act run aw app role revoke again with --replace %s",
			saved.OperationID, unfinishedState(saved.Quarantine), saved.OperationID))
	}
	binding, err := profile.BindingFor(scope)
	if err != nil {
		return err
	}
	var frozen map[string]any
	opts, _ := optionsFor(scope)
	opts.CheckPrepared = ownerActCheck(binding.AuthorityKeyDID, &frozen)
	receipt, err := handoff.Resume(ctx, opts, saved.Body)
	return settleProtectedAct(cmd, saved.OperationID, frozen, binding, receipt, err)
}

// ownerActCheck accepts a verified prepared owner act only when its intent's
// template names the team key the profile pins. It keeps the frozen request
// it accepted in kept.
func ownerActCheck(teamKeyDID string, kept *map[string]any) func(context.Context, map[string]any) error {
	return func(_ context.Context, request map[string]any) error {
		template, err := handoff.IntentTemplate(request)
		if err != nil {
			return err
		}
		if template["team_key_did"] != teamKeyDID {
			return withErrorCode("operation_mismatch", errors.New("the prepared act is signed by another team key than the profile pins"))
		}
		*kept = request
		return nil
	}
}

// settleProtectedAct ends a protected operation. A refused one is forgotten.
// A committed one is settled only by the service's applied receipt: the app
// applied, with exact confirmation, the act the service issued under the
// human's approval of frozen, the verified frozen intent, signed by the team
// key the profile pins. aw never delivers a protected act itself; a signed
// act without that confirmation, or one aw cannot verify, keeps the saved
// request for aw app role resume to read again.
func settleProtectedAct(cmd *cobra.Command, operationID string, frozen map[string]any, binding *handoff.ProfileBinding, receipt *handoff.Receipt, err error) error {
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperation(cmd, operationID)
	}
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return withErrorCode(code, fmt.Errorf("%w (operation %s)", err, operationID))
		}
		return err
	}
	if receipt == nil || receipt.State != "committed" {
		return withErrorCode("signed_act_invalid", fmt.Errorf("operation %s has no committed result", operationID))
	}
	if result, ok := handoff.DecodeObject(receipt.Result); !ok || result["v"] == nil {
		return withErrorCode("application_unconfirmed", fmt.Errorf(
			"operation %s is signed, but the protected service has not confirmed the app applied it, and aw does not deliver protected acts; its request is kept, and aw app role resume %s reads its receipt again", operationID, operationID))
	}
	signed, err := appliedActFor(operationID, frozen, binding.AuthorityKeyDID, receipt.Result, time.Now())
	if err != nil {
		return fmt.Errorf("operation %s: %w", operationID, err)
	}
	act, _ := handoff.DecodeObject(bytes.TrimPrefix(signed.Signing, []byte(awid.OwnerActPrefix)))
	if err := handoff.VerifyIssuedArtifact(frozen, act); err != nil {
		return withErrorCode("signed_act_invalid", fmt.Errorf("operation %s: the applied act is not the act the human approved: %w", operationID, err))
	}
	forgetProtectedOperation(cmd, operationID)
	printOutput(map[string]any{"operation_id": operationID, "state": "committed", "result": json.RawMessage(receipt.Result), "applied": "service"},
		func(any) string {
			return fmt.Sprintf("Operation %s committed; %s was applied by the protected service.\n", operationID, signed.Act)
		})
	return nil
}

func forgetProtectedOperation(cmd *cobra.Command, operationID string) {
	if err := awconfig.RemovePendingGovernanceOperation(operationID); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Operation %s is settled, but its saved request could not be removed: %v\n", operationID, err)
	}
}

// signedAct is the owner act a committed protected operation carries.
type signedAct struct {
	Act, Audience string
	Signing       []byte
	Signature     string
}

// signedActFor is the act in a committed receipt's result, if it is exactly
// the act aw requested in intent (act, team, audience and subject), signed
// by authorityKeyDID, the controller key the operator's profile pins, and
// still valid at now. Anything else is signed_act_invalid and is not sent.
func signedActFor(intent map[string]any, authorityKeyDID string, result []byte, now time.Time) (*signedAct, error) {
	invalid := func(format string, args ...any) error {
		return withErrorCode("signed_act_invalid", fmt.Errorf("the signed act is not the act aw requested: "+format, args...))
	}
	fields, ok := handoff.DecodeObject(result)
	signingText, _ := fields["signing"].(string)
	signature, _ := fields["signature"].(string)
	if !ok || len(fields) != 2 || signingText == "" || signature == "" {
		return nil, invalid("the receipt's result is not exactly a signing and a signature")
	}
	// Go's strict base64 still skips CR and LF; one spelling is accepted.
	if strings.ContainsAny(signingText+signature, "\r\n") {
		return nil, invalid("its signing or signature has a line break")
	}
	signing, err := base64.StdEncoding.Strict().DecodeString(signingText)
	if err != nil {
		return nil, invalid("its signing bytes are not base64")
	}
	// The service writes the 64-byte signature in padded base64; the owner-act
	// contract spells it unpadded, and that canonical spelling is verified and sent.
	raw, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, invalid("its signature is not 64 bytes of padded base64")
	}
	signature = base64.RawStdEncoding.EncodeToString(raw)
	act, _ := intent["operation"].(string)
	audience, _ := intent["audience"].(string)
	subject, _ := intent["subject"].(map[string]any)
	scope, _ := intent["scope"].(map[string]any)
	authority, _ := scope["authority"].(map[string]any)
	teamID, _ := authority["id"].(string)
	if _, err := awid.VerifyOwnerAct(signing, signature, awid.OwnerActVerifyOptions{
		TeamID: teamID, CurrentTeamKeyDID: authorityKeyDID, Audience: audience, Acts: []string{act},
		Now: now, ExpectedSubject: subject, NonceUsed: func(string) bool { return false },
	}); err != nil {
		return nil, invalid("%v", err)
	}
	return &signedAct{Act: act, Audience: audience, Signing: signing, Signature: signature}, nil
}

// roleActReading reads a committed receipt of an unfinished role act aw will
// not continue. It settles only a service-applied act that verifies under
// the original rules and the profile's key for the request's own scope, as
// history; a changed key or a missing binding is not historical
// verification. A bare signed act is kept with its bytes, its signature
// checked under those rules, and marked expired once past its lifetime at
// now; it is never sent.
func roleActReading(profile *handoff.Profile, now time.Time) committedReading {
	return func(saved *awconfig.PendingGovernanceOperation, body map[string]any, result []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
		unverifiable := &awconfig.GovernanceQuarantine{State: "committed", Verification: "unverifiable"}
		scope, _ := body["scope"].(map[string]any)
		binding, err := profile.BindingFor(scope)
		if err != nil {
			return nil, unverifiable
		}
		if fields, ok := handoff.DecodeObject(result); ok && fields["v"] != nil {
			signed, err := appliedActFor(saved.OperationID, body, binding.AuthorityKeyDID, result, now)
			if err != nil {
				return nil, unverifiable
			}
			return map[string]any{"operation_id": saved.OperationID, "state": "committed", "act": signed.Act, "applied": "service"}, nil
		}
		signing, signature, reason := signedResult(result)
		if reason != "" {
			return nil, unverifiable
		}
		facts := &awconfig.GovernanceQuarantine{State: "committed", Signing: signing, Signature: signature, Verification: "unverifiable"}
		act, _ := handoff.DecodeObject(bytes.TrimPrefix(signing, []byte(awid.OwnerActPrefix)))
		issuedText, _ := act["issued_at"].(string)
		expiresText, _ := act["expires_at"].(string)
		issued, errIssued := time.Parse(time.RFC3339, issuedText)
		expires, errExpires := time.Parse(time.RFC3339, expiresText)
		if errIssued != nil || errExpires != nil {
			return nil, facts
		}
		if _, err := signedActFor(body, binding.AuthorityKeyDID, result, issued); err != nil {
			return nil, facts
		}
		facts.Verification = "signature_verified"
		if !now.Before(expires) {
			facts.Verification = "expired"
		}
		return nil, facts
	}
}
