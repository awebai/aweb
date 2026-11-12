package main

import (
	"bytes"
	"cmp"
	"context"
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
	path := strings.TrimSpace(appProtectedProfileFlag)
	if path == "" {
		return nil, usageError("--protected-profile is required")
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
	return map[string]any{"operation": act, "variant": "default", "scope": scope, "audience": audience, "subject": subject}
}

// protectedRequesterSigner sends requests to the profile's request origin as
// this identity, proving it with a freshly timestamped covering-v2 envelope
// over scope. Redirects are never followed.
func protectedRequesterSigner(profile *handoff.Profile, scope map[string]any, identity *localSigningIdentity) handoff.Signer {
	return func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
		headers, err := handoff.ProtectedRequestHeaders(handoff.ProtectedRequest{
			Profile: profile, Scope: scope, RequesterID: identity.StableID,
			Method: method, Path: target.EscapedPath(), Body: body,
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
		// The saved request is removed by settleProtectedAct, not on a
		// committed receipt: a signed act not yet delivered stays resumable.
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
	operationID, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s for %s on %s, approved by %s through %s\n", act, subject["principal"], subject["app_id"], appApproverFlag, profile.ServiceID)
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	intent := protectedRoleIntent(act, binding.Scope, audience, subject)
	receipt, err := handoff.Approve(ctx, governanceOptions(cmd, profile, binding.Scope, identity), operationID, intent)
	return settleProtectedAct(cmd, operationID, intent, binding, receipt, err)
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
	scope, err := savedScope(profile, saved.Body)
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	binding, err := profile.BindingFor(scope)
	if err != nil {
		return err
	}
	intent, _ := handoff.DecodeObject(saved.Body)
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	receipt, err := handoff.Resume(ctx, governanceOptions(cmd, profile, scope, identity), saved.Body)
	return settleProtectedAct(cmd, operationID, intent, binding, receipt, err)
}

// settleProtectedAct ends a protected operation. A refused one is forgotten.
// A committed one carries the act the service signed: aw checks it is exactly
// the act it requested, under the authority key the profile pins, and
// delivers it to the app's owner-act route. The saved request is forgotten
// only once the app has applied the act, so an undelivered act can be
// resumed and delivered again; it is never re-signed.
func settleProtectedAct(cmd *cobra.Command, operationID string, intent map[string]any, binding *handoff.ProfileBinding, receipt *handoff.Receipt, err error) error {
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperation(cmd, operationID)
	}
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return withErrorCode(code, fmt.Errorf("operation %s: %w", operationID, err))
		}
		return err
	}
	signed, err := signedActFor(intent, binding.AuthorityKeyDID, receipt.Result, time.Now())
	if err != nil {
		return fmt.Errorf("operation %s: %w", operationID, err)
	}
	report := map[string]any{"operation_id": operationID, "state": receipt.State, "result": json.RawMessage(receipt.Result)}
	applied, err := deliverOwnerAct(cmd, signed.Audience, humanRoleActRequest{Act: signed.Act}.deliveryBody(signed.Signing, signed.Signature))
	switch {
	case errorCodeOf(err) == "nonce_reused":
		// The app consumes an act's nonce only with its effect, so this act
		// already took effect on an earlier delivery.
		report["applied"] = "earlier"
	case err != nil:
		return withErrorCode(cmp.Or(errorCodeOf(err), "owner_act_undelivered"), fmt.Errorf(
			"operation %s is signed but the app did not apply it: %w; deliver it again with aw app role resume %s --protected-profile <profile>", operationID, err, operationID))
	default:
		report["applied"] = applied
	}
	forgetProtectedOperation(cmd, operationID)
	printOutput(report, func(any) string {
		if report["applied"] == "earlier" {
			return fmt.Sprintf("Operation %s committed; %s had already taken effect.\n", operationID, signed.Act)
		}
		return fmt.Sprintf("Operation %s committed; %s for %s took effect at %s.\n", operationID, applied["act"], applied["principal"], applied["effective_at"])
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
	signing, err := base64.StdEncoding.Strict().DecodeString(signingText)
	if err != nil {
		return nil, invalid("its signing bytes are not base64")
	}
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
