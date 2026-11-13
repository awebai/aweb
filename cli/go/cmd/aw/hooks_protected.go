package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

func hookProfile(path string) (*handoff.Profile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, usageError("--protected-profile and --approver are required for live hook activation")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return handoff.ParseProfile(raw)
}

func runProtectedHookActivate(cmd *cobra.Command, appID, bindingID, profilePath, approver string) error {
	profile, err := hookProfile(profilePath)
	if err != nil {
		return err
	}
	client, selection, err := resolveClientSelection()
	if err != nil {
		return err
	}
	binding, err := protectedBinding(profile, selection.TeamID, strings.TrimSpace(approver))
	if err != nil {
		return err
	}
	audience, err := ownerActAudience(selection.BaseURL)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	listed, err := listHookBindings(ctx, client, selection.TeamID, appID)
	if err != nil {
		return err
	}
	var selected *hookBinding
	for i := range listed.Bindings {
		if listed.Bindings[i].BindingID == bindingID {
			selected = &listed.Bindings[i]
		}
	}
	if selected == nil || selected.TeamID != selection.TeamID || selected.AppID != appID {
		return withErrorCode("binding_not_found", fmt.Errorf("no matching binding in this team and app"))
	}
	if selected.State != "pending" {
		return withErrorCode("binding_not_live", fmt.Errorf("binding %s is %s", bindingID, selected.State))
	}
	subject, err := declaredBindingSubject(*selected)
	if err != nil {
		return err
	}
	intent, err := protectedHookIntent(binding, audience, subject)
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
	return settleProtectedHook(cmd, client, id, intent, binding, receipt, err)
}

func protectedHookIntent(binding *handoff.ProfileBinding, audience string, subject map[string]any) (map[string]any, error) {
	// Saved JSON numbers pass through the shared subject normalizer too. No
	// verifier compares a json.Number to an int64 as if it were a different act.
	normalized, err := awid.ValidateOwnerActSubject("hook-binding.activate", subject)
	if err != nil {
		return nil, err
	}
	return protectedRoleIntent("hook-binding.activate", binding.Scope, audience, normalized), nil
}

func settleProtectedHook(cmd *cobra.Command, client *aweb.Client, id string, intent map[string]any, binding *handoff.ProfileBinding, receipt *handoff.Receipt, operationErr error) error {
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperation(cmd, id)
	}
	if operationErr != nil {
		return operationErr
	}
	if receipt == nil || receipt.OperationID != id || receipt.State != "committed" {
		return withErrorCode("receipt_unavailable", fmt.Errorf("operation %s has no matching committed receipt; its request is kept", id))
	}
	// This adapter accepts exactly its one typed consumer, never another act or
	// audience from a response. The ordinary coordination client owns transport.
	if intent["operation"] != "hook-binding.activate" || intent["variant"] != "default" {
		return withErrorCode("intent_invalid", fmt.Errorf("not a hook activation"))
	}
	scope, ok := intent["scope"].(map[string]any)
	if !ok {
		return usageError("saved scope is missing")
	}
	authority, _ := scope["authority"].(map[string]any)
	if authority["kind"] != "team_controller" {
		return usageError("hook activation requires a team controller")
	}
	subject, _ := intent["subject"].(map[string]any)
	normalized, err := awid.ValidateOwnerActSubject("hook-binding.activate", subject)
	if err != nil {
		return err
	}
	exact := map[string]any{}
	for key, value := range intent {
		exact[key] = value
	}
	exact["subject"] = normalized
	signed, err := signedActFor(exact, binding.AuthorityKeyDID, receipt.Result, time.Now())
	if err != nil {
		return err
	}
	var applied hookBinding
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	target := "/v1/apps/hook-bindings/" + url.PathEscape(normalized["binding_id"].(string)) + "/activate"
	if err := client.Post(ctx, target, map[string]string{"act": base64.StdEncoding.EncodeToString(signed.Signing), "signature": signed.Signature}, &applied); err != nil {
		return withErrorCode("owner_act_undelivered", fmt.Errorf("operation %s is signed but activation is unconfirmed: %w; request kept; resume with aw hooks resume %s --protected-profile <profile>", id, err, id))
	}
	confirmed, err := hookBindingRowSubject(applied)
	if err != nil || applied.State != "active" || applied.TeamID != authority["id"] {
		return withErrorCode("effect_unconfirmed", fmt.Errorf("activation reply does not acknowledge this binding; request kept"))
	}
	left, err := awid.StrictCanonicalJSON(normalized)
	if err != nil {
		return err
	}
	right, err := awid.StrictCanonicalJSON(confirmed)
	if err != nil || string(left) != string(right) {
		return withErrorCode("effect_unconfirmed", fmt.Errorf("activation reply names a different binding; request kept"))
	}
	forgetProtectedOperation(cmd, id)
	printOutput(map[string]any{"operation_id": id, "state": "committed", "applied": applied}, func(any) string {
		return fmt.Sprintf("Operation %s committed; binding %s is active.\n", id, applied.BindingID)
	})
	return nil
}

func protectedHookResumeCmd() *cobra.Command {
	var profilePath string
	cmd := &cobra.Command{Use: "resume <operation-id>", Short: "Resume delivery of the same protected hook activation", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		profile, err := hookProfile(profilePath)
		if err != nil {
			return err
		}
		saved, err := pendingOperationFor(profile, args[0])
		if err != nil {
			return err
		}
		intent, ok := handoff.DecodeObject(saved.Body)
		if !ok || intent["operation_id"] != args[0] || intent["operation"] != "hook-binding.activate" || intent["variant"] != "default" {
			return usageError("saved request is not this hook activation")
		}
		scope, err := savedScope(profile, saved.Body)
		if err != nil {
			return err
		}
		binding, err := profile.BindingFor(scope)
		if err != nil {
			return err
		}
		client, selection, err := resolveClientSelection()
		if err != nil {
			return err
		}
		audience, err := ownerActAudience(selection.BaseURL)
		if err != nil {
			return err
		}
		authority, _ := scope["authority"].(map[string]any)
		if authority["id"] != selection.TeamID || intent["audience"] != audience {
			return usageError("resume must use the original team and coordination origin")
		}
		subject, _ := intent["subject"].(map[string]any)
		if _, err := protectedHookIntent(binding, audience, subject); err != nil {
			return err
		}
		identity, err := resolveLocalSigningIdentity()
		if err != nil {
			return err
		}
		opts := governanceOptions(cmd, profile, scope, identity)
		opts.Forget = nil
		receipt, err := handoff.Resume(cmd.Context(), opts, saved.Body)
		return settleProtectedHook(cmd, client, args[0], intent, binding, receipt, err)
	}}
	cmd.Flags().StringVar(&profilePath, "protected-profile", "", "The original protected-service profile")
	return cmd
}
