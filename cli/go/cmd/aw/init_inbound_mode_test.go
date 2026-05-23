package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// aapl.7 — Go CLI --inbound-mode flag tests.
//
// Two layers:
//   1. validateInitInboundMode parse-time tests (no network) cover the
//      flag-shape contract: only {open, team-and-contacts} on --global,
//      reject on local, reject the withdrawn third value.
//   2. runAPIKeyBootstrapInit payload tests using the existing
//      newLocalHTTPServer fixture cover the wire-level translation
//      (team-and-contacts -> team_and_contacts in the POST body, omitted when
//      the flag is unset).
//
// The user-facing flag value is hyphen-spelled (team-and-contacts) per
// Juan's CLI convention; the wire/API value stays underscored
// (team_and_contacts).

// resetInboundModeFlags resets package-level CLI state between tests.
func resetInboundModeFlags() {
	initInboundMode = ""
	initPersistent = false
	initBYOD = false
}

func TestValidateInitInboundModeAcceptsContactsOnlyWithGlobal(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "team-and-contacts"
	initPersistent = true
	if err := validateInitInboundMode(); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if initInboundMode != "team-and-contacts" {
		t.Fatalf("normalized value=%q want team-and-contacts", initInboundMode)
	}
	if got := canonicalInitInboundModeForWire(initInboundMode); got != "team_and_contacts" {
		t.Fatalf("wire form=%q want team_and_contacts", got)
	}
}

func TestValidateInitInboundModeAcceptsOpenWithGlobal(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "open"
	initPersistent = true
	if err := validateInitInboundMode(); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if got := canonicalInitInboundModeForWire(initInboundMode); got != "open" {
		t.Fatalf("wire form=%q want open", got)
	}
}

func TestValidateInitInboundModeOmittedYieldsEmptyWireValue(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = ""
	initPersistent = true
	if err := validateInitInboundMode(); err != nil {
		t.Fatalf("expected accept of empty value, got %v", err)
	}
	if got := canonicalInitInboundModeForWire(initInboundMode); got != "" {
		t.Fatalf("wire form for empty flag=%q want empty", got)
	}
}

func TestValidateInitInboundModeRejectsContactsOnlyOnLocal(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "team-and-contacts"
	initPersistent = false
	err := validateInitInboundMode()
	if err == nil {
		t.Fatal("expected --inbound-mode on local to fail at parse time")
	}
	if !strings.Contains(err.Error(), "--global") {
		t.Fatalf("error should mention --global; got %v", err)
	}
}

func TestValidateInitInboundModeRejectsWithdrawnContactsOrTeammatesUnderscore(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "contacts_or_teammates"
	initPersistent = true
	err := validateInitInboundMode()
	if err == nil {
		t.Fatal("expected contacts_or_teammates to be rejected at parse time")
	}
	if !strings.Contains(err.Error(), "contacts_or_teammates") {
		t.Fatalf("error should echo the invalid value; got %v", err)
	}
	if !strings.Contains(err.Error(), "open") || !strings.Contains(err.Error(), "team-and-contacts") {
		t.Fatalf("error should describe valid values; got %v", err)
	}
}

func TestValidateInitInboundModeRejectsWithdrawnContactsOrTeammatesHyphen(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "contacts-or-teammates"
	initPersistent = true
	if err := validateInitInboundMode(); err == nil {
		t.Fatal("expected hyphenated contacts-or-teammates to be rejected")
	}
}

func TestValidateInitInboundModeRejectsUnknownValue(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "team-only"
	initPersistent = true
	if err := validateInitInboundMode(); err == nil {
		t.Fatal("expected unknown value to be rejected")
	}
}

// BYOD path currently has no server-side creation endpoint to carry
// the value. Fail-fast instead of silently dropping the choice
// (Juan c2d25276 + Grace 68bcc81c).
func TestValidateInitInboundModeRejectsBYODGlobal(t *testing.T) {
	t.Cleanup(resetInboundModeFlags)
	initInboundMode = "team-and-contacts"
	initPersistent = true
	initBYOD = true
	err := validateInitInboundMode()
	if err == nil {
		t.Fatal("expected --byod + --inbound-mode to fail at parse time")
	}
	if !strings.Contains(err.Error(), "--byod") {
		t.Fatalf("error should mention --byod path; got %v", err)
	}
	if !strings.Contains(err.Error(), "dashboard") && !strings.Contains(err.Error(), "PATCH") {
		t.Fatalf("error should suggest a real follow-up path; got %v", err)
	}
}

// provisionHostedIdentity payload coverage: confirm the
// /api/v1/onboarding/cli-signup body carries the canonical
// underscored inbound_mode when the wizard passes a value, and the
// field is omitted when the value is unset. Mirrors the contract for
// the guided hosted-onboarding global creation path.

func TestProvisionHostedIdentityForwardsInboundModeContactsOnly(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	_ = teamDIDKey
	var signupBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/did":
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			didAW := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": "did:key:placeholder",
				"created_at":      "2026-05-22T00:00:00Z",
				"updated_at":      "2026-05-22T00:00:00Z",
			})
		case r.URL.Path == "/api/v1/onboarding/cli-signup":
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := signupBody["did_key"].(string)
			didAW, _ := signupBody["did_aw"].(string)
			cert, certErr := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:alice.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "alice.aweb.ai/laptop",
				Alias:         "laptop",
				Lifetime:      awid.LifetimePersistent,
			})
			if certErr != nil {
				t.Fatal(certErr)
			}
			encoded, encErr := awid.EncodeTeamCertificateHeader(cert)
			if encErr != nil {
				t.Fatal(encErr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         "alice",
				"org_id":           "org-1",
				"namespace_domain": "alice.aweb.ai",
				"team_id":          "default:alice.aweb.ai",
				"api_key":          "aw_sk_hosted_workspace",
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "alice.aweb.ai/laptop",
				"alias":            "laptop",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	_, err = provisionHostedIdentity(server.URL, server.URL, "alice", "laptop", true, "team_and_contacts")
	if err != nil {
		t.Fatalf("provisionHostedIdentity: %v", err)
	}
	wire, ok := signupBody["inbound_mode"].(string)
	if !ok {
		t.Fatalf("cli-signup body should carry inbound_mode; got %v", signupBody["inbound_mode"])
	}
	if wire != "team_and_contacts" {
		t.Fatalf("inbound_mode=%q want team_and_contacts", wire)
	}
}

func TestProvisionHostedIdentityOmitsInboundModeWhenUnset(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = awid.ComputeDIDKey(teamPub)
	var signupBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/did":
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			didAW := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": "did:key:placeholder",
				"created_at":      "2026-05-22T00:00:00Z",
				"updated_at":      "2026-05-22T00:00:00Z",
			})
		case r.URL.Path == "/api/v1/onboarding/cli-signup":
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := signupBody["did_key"].(string)
			didAW, _ := signupBody["did_aw"].(string)
			cert, certErr := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:bob.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "bob.aweb.ai/laptop",
				Alias:         "laptop",
				Lifetime:      awid.LifetimePersistent,
			})
			if certErr != nil {
				t.Fatal(certErr)
			}
			encoded, encErr := awid.EncodeTeamCertificateHeader(cert)
			if encErr != nil {
				t.Fatal(encErr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-2",
				"username":         "bob",
				"org_id":           "org-2",
				"namespace_domain": "bob.aweb.ai",
				"team_id":          "default:bob.aweb.ai",
				"api_key":          "aw_sk_hosted_workspace",
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "bob.aweb.ai/laptop",
				"alias":            "laptop",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	// Pass "" for inboundMode → field must be omitted from the wire body.
	_, err = provisionHostedIdentity(server.URL, server.URL, "bob", "laptop", true, "")
	if err != nil {
		t.Fatalf("provisionHostedIdentity: %v", err)
	}
	if v, ok := signupBody["inbound_mode"]; ok {
		t.Fatalf("cli-signup body should omit inbound_mode when unset; got %v", v)
	}
}

// runAPIKeyBootstrapInit payload coverage: confirm the wire body
// carries the canonical underscored value when the user passed the
// hyphen flag, and that the field is omitted when the flag is unset.

func TestRunAPIKeyBootstrapInitForwardsInboundModeContactsOnly(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")

	const apiKey = "aw_sk_test_inbound_mode"
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var initBody map[string]any
	var registeredDIDKey string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/did":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			registeredDIDKey, _ = body["new_did_key"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": registeredDIDKey,
				"created_at":      "2026-04-18T00:00:00Z",
				"updated_at":      "2026-04-18T00:00:00Z",
			})
		case r.URL.Path == "/api/v1/workspaces/init":
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := initBody["did"].(string)
			pubKeyB64, _ := initBody["public_key"].(string)
			pubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
			stableID := awid.ComputeStableID(ed25519.PublicKey(pubKeyBytes))
			memberAddress := "alice.aweb.ai/alice"
			cert, certErr := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:alice.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   stableID,
				MemberAddress: memberAddress,
				Alias:         "alice",
				Lifetime:      awid.LifetimePersistent,
			})
			if certErr != nil {
				t.Fatal(certErr)
			}
			encoded, encErr := awid.EncodeTeamCertificateHeader(cert)
			if encErr != nil {
				t.Fatal(encErr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "default:alice.aweb.ai",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      stableID,
				"identity_scope": awid.IdentityModeGlobal,
				"custody":        awid.CustodySelf,
				"api_key":        "workspace-sk-persistent",
			})
		case r.URL.Path == "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:alice.aweb.ai",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir:  tmp,
		AwebURL:     externalLikeTestURL(t, server.URL),
		RegistryURL: server.URL,
		APIKey:      apiKey,
		Name:        "alice",
		Role:        "backend",
		HumanName:   "Alice",
		AgentType:   "codex",
		Persistent:  true,
		InboundMode: "team_and_contacts", // canonical wire form post-validation
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit: %v", err)
	}
	wire, ok := initBody["inbound_mode"].(string)
	if !ok {
		t.Fatalf("workspaces/init body should carry inbound_mode; got %v", initBody["inbound_mode"])
	}
	if wire != "team_and_contacts" {
		t.Fatalf("inbound_mode=%q want team_and_contacts", wire)
	}
}

func TestRunAPIKeyBootstrapInitOmitsInboundModeWhenUnset(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")

	const apiKey = "aw_sk_test_no_inbound_mode"
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var initBody map[string]any
	var registeredDIDKey string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/did":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			registeredDIDKey, _ = body["new_did_key"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": registeredDIDKey,
				"created_at":      "2026-04-18T00:00:00Z",
				"updated_at":      "2026-04-18T00:00:00Z",
			})
		case r.URL.Path == "/api/v1/workspaces/init":
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := initBody["did"].(string)
			pubKeyB64, _ := initBody["public_key"].(string)
			pubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
			stableID := awid.ComputeStableID(ed25519.PublicKey(pubKeyBytes))
			memberAddress := "alice.aweb.ai/alice"
			cert, certErr := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:alice.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   stableID,
				MemberAddress: memberAddress,
				Alias:         "alice",
				Lifetime:      awid.LifetimePersistent,
			})
			if certErr != nil {
				t.Fatal(certErr)
			}
			encoded, encErr := awid.EncodeTeamCertificateHeader(cert)
			if encErr != nil {
				t.Fatal(encErr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "default:alice.aweb.ai",
				"workspace_id":   "ws-2",
				"did":            didKey,
				"stable_id":      stableID,
				"identity_scope": awid.IdentityModeGlobal,
				"custody":        awid.CustodySelf,
				"api_key":        "workspace-sk-no-inbound",
			})
		case r.URL.Path == "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:alice.aweb.ai",
				"alias":        "alice",
				"agent_id":     "agent-2",
				"workspace_id": "ws-2",
				"repo_id":      "repo-2",
				"team_did_key": teamDIDKey,
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir:  tmp,
		AwebURL:     externalLikeTestURL(t, server.URL),
		RegistryURL: server.URL,
		APIKey:      apiKey,
		Name:        "alice",
		Role:        "backend",
		HumanName:   "Alice",
		AgentType:   "codex",
		Persistent:  true,
		// InboundMode intentionally unset → field must be omitted.
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit: %v", err)
	}
	if v, ok := initBody["inbound_mode"]; ok {
		t.Fatalf("workspaces/init body should omit inbound_mode when unset; got %v", v)
	}
}
