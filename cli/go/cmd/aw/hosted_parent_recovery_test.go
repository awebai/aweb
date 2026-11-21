package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedExplicitParentSurvivesPreviewOutage(t *testing.T) {
	wd, parent := t.TempDir(), t.TempDir()
	previews := 0
	service := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/spawn/invite-preview" {
			t.Error("parent choice disappeared before submission")
			http.Error(w, "unexpected submission", 500)
			return
		}
		previews++
		if previews == 1 {
			http.Error(w, "preview unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": nil})
	})
	opts := teamAcceptInviteOptions{Name: "child", Scope: "local", AwebURL: service.URL, ParentHome: parent}
	want, err := normalizeInviteParentHome(parent)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: wd, Token: "aw_inv_explicit_retry", Options: opts}); err == nil {
			t.Fatal("unavailable preview or unavailable explicit parent did not refuse")
		}
		state, err := loadHostedInviteCreation(filepath.Join(wd, ".aw", hostedInviteRecoveryFile))
		if err != nil || state == nil || state.ParentHome != want || (state.MintedKey == nil || !*state.MintedKey) {
			t.Fatalf("lost selected parent or key provenance: %+v %v", state, err)
		}
		opts.ParentHome = "" // A retry uses the retained selection.
	}
}

func TestHostedParentSelectionIsFrozenBeforeSubmission(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		t.Run(map[bool]string{false: "not submitted", true: "uncertain"}[attempted], func(t *testing.T) {
			state := &hostedInviteCreation{AcceptAttempted: &attempted, IssuerCreationStarted: true}
			parent := t.TempDir()
			got, err := state.selectParent(parent)
			if attempted {
				if err == nil {
					t.Fatal("changed parent after possible effect")
				}
				return
			}
			if err != nil || got == "" || state.IssuerCreationStarted {
				t.Fatalf("new explicit creator not selected: %v", err)
			}
			saved, err := state.selectParent("")
			if err != nil || saved != got {
				t.Fatal("omitted parent lost original selection")
			}
			if _, err := state.selectParent(t.TempDir()); err == nil {
				t.Fatal("changed frozen creator")
			}
		})
	}
}

func TestHostedRefusalReleaseRequiresKnownCodeAndUncertainStateExplainsExit(t *testing.T) {
	for _, c := range []struct {
		status     int
		body       string
		definitive bool
	}{
		{409, `{"detail":{"code":"human_condition_mismatch","message":"wrong human"}}`, true},
		{503, `{"detail":{"code":"human_condition_mismatch","message":"outage"}}`, false},
		{403, `{"detail":{"code":"human_condition_mismatch","message":"wrong status"}}`, false},
		{409, `{"detail":"Invite token use limit reached"}`, false},
		{410, `{"detail":"Invite token expired or revoked"}`, false},
		{409, `{"reason":"accepted_identity_mismatch"}`, false},
		{409, `not json`, false},
		{http.StatusGatewayTimeout, `{"reason":"human_condition_mismatch"}`, false},
	} {
		err := &awid.APIError{StatusCode: c.status, Body: c.body}
		if got := hostedInviteDefinitiveRefusal(err); got != c.definitive {
			t.Fatalf("classification %d %s: %v", c.status, c.body, got)
		}
	}
	home := t.TempDir()
	err := uncertainHostedInviteError(home, "backend:example.com", errors.New("retry refused"))
	for _, part := range []string{"earlier attempt may have succeeded", filepath.Join(home, hostedInviteRecoveryFile), "fetch-cert", "--namespace example.com --team backend", "If it is not"} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("missing reconciliation exit %q", part)
		}
	}
}

func TestPendingHostedCertificateFetchIsNarrow(t *testing.T) {
	oldTeam, oldDomain, oldID := teamFetchCertTeam, teamFetchCertNamespace, teamFetchCertID
	oldHuman := humanFlag
	t.Cleanup(func() {
		teamFetchCertTeam, teamFetchCertNamespace, teamFetchCertID = oldTeam, oldDomain, oldID
		humanFlag = oldHuman
	})
	humanFlag = ""
	home := awconfig.IdentityHome{Root: t.TempDir(), Source: awconfig.IdentityHomeFlag}
	pub, key, _ := awid.GenerateKeypair()
	awid.SaveSigningKey(filepath.Join(home.Root, "signing.key"), key)
	tree, _ := newHostedIDTreeRecovery(hostedIdentityContext{})
	state := &hostedInviteCreation{Tree: tree, TokenHash: "original", DIDKey: awid.ComputeDIDKey(pub), Scope: "local", TeamID: "backend:example.com"}
	if err := state.save(filepath.Join(home.Root, hostedInviteRecoveryFile)); err != nil {
		t.Fatal(err)
	}
	teamFetchCertTeam, teamFetchCertNamespace, teamFetchCertID = "backend", "example.com", "certificate-from-service"
	ok, err := pendingHostedExchangeTarget(teamFetchCertCmd, home)
	if err != nil || !ok {
		t.Fatalf("reconciliation command cannot use its pending home: %v", err)
	}
	humanFlag = installedChainHuman
	if ok, err := pendingHostedExchangeTarget(teamFetchCertCmd, home); err != nil || ok {
		t.Fatal("human selection borrowed the pending agent's identity")
	}
	humanFlag = ""
	teamFetchCertTeam = "another"
	ok, err = pendingHostedExchangeTarget(teamFetchCertCmd, home)
	if err != nil || ok {
		t.Fatal("pending fetch escaped original team")
	}
	ok, err = pendingHostedExchangeTarget(mailInboxCmd, home)
	if err != nil || ok {
		t.Fatal("pending home became general acting identity")
	}
}
