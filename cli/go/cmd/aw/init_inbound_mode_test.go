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
//      flag-shape contract: only {open, contacts-only} on --global,
//      reject on local, reject the withdrawn third value.
//   2. runAPIKeyBootstrapInit payload tests using the existing
//      newLocalHTTPServer fixture cover the wire-level translation
//      (contacts-only -> contacts_only in the POST body, omitted when
//      the flag is unset).
//
// The user-facing flag value is hyphen-spelled (contacts-only) per
// Juan's CLI convention; the wire/API value stays underscored
// (contacts_only).

func TestValidateInitInboundModeAcceptsContactsOnlyWithGlobal(t *testing.T) {
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
	initInboundMode = "contacts-only"
	initPersistent = true
	if err := validateInitInboundMode(); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if initInboundMode != "contacts-only" {
		t.Fatalf("normalized value=%q want contacts-only", initInboundMode)
	}
	if got := canonicalInitInboundModeForWire(initInboundMode); got != "contacts_only" {
		t.Fatalf("wire form=%q want contacts_only", got)
	}
}

func TestValidateInitInboundModeAcceptsOpenWithGlobal(t *testing.T) {
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
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
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
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
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
	initInboundMode = "contacts-only"
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
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
	initInboundMode = "contacts_or_teammates"
	initPersistent = true
	err := validateInitInboundMode()
	if err == nil {
		t.Fatal("expected contacts_or_teammates to be rejected at parse time")
	}
	if !strings.Contains(err.Error(), "contacts_or_teammates") {
		t.Fatalf("error should echo the invalid value; got %v", err)
	}
	if !strings.Contains(err.Error(), "open") || !strings.Contains(err.Error(), "contacts-only") {
		t.Fatalf("error should describe valid values; got %v", err)
	}
}

func TestValidateInitInboundModeRejectsWithdrawnContactsOrTeammatesHyphen(t *testing.T) {
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
	initInboundMode = "contacts-or-teammates"
	initPersistent = true
	if err := validateInitInboundMode(); err == nil {
		t.Fatal("expected hyphenated contacts-or-teammates to be rejected")
	}
}

func TestValidateInitInboundModeRejectsUnknownValue(t *testing.T) {
	t.Cleanup(func() {
		initInboundMode = ""
		initPersistent = false
	})
	initInboundMode = "team-only"
	initPersistent = true
	if err := validateInitInboundMode(); err == nil {
		t.Fatal("expected unknown value to be rejected")
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
		InboundMode: "contacts_only", // canonical wire form post-validation
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit: %v", err)
	}
	wire, ok := initBody["inbound_mode"].(string)
	if !ok {
		t.Fatalf("workspaces/init body should carry inbound_mode; got %v", initBody["inbound_mode"])
	}
	if wire != "contacts_only" {
		t.Fatalf("inbound_mode=%q want contacts_only", wire)
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
