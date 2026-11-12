package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
			Sign: func(payload []byte) (string, []byte, error) {
				return identity.DIDKey, ed25519.Sign(identity.SigningKey, payload), nil
			},
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
		Forget: awconfig.RemovePendingGovernanceOperation,
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
	receipt, err := handoff.Approve(ctx, governanceOptions(cmd, profile, binding.Scope, identity), operationID, protectedRoleIntent(act, binding.Scope, audience, subject))
	return reportProtectedReceipt(operationID, receipt, err)
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
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	receipt, err := handoff.Resume(ctx, governanceOptions(cmd, profile, scope, identity), saved.Body)
	return reportProtectedReceipt(operationID, receipt, err)
}

func reportProtectedReceipt(operationID string, receipt *handoff.Receipt, err error) error {
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return withErrorCode(code, fmt.Errorf("operation %s: %w", operationID, err))
		}
		return err
	}
	printOutput(map[string]any{"operation_id": receipt.OperationID, "state": receipt.State, "result": json.RawMessage(receipt.Result)}, func(value any) string {
		return fmt.Sprintf("Operation %s committed.\n", operationID)
	})
	return nil
}
