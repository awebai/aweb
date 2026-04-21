package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIDNamespaceAssignAddressHappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	subjectPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectDID := awid.ComputeDIDKey(subjectPub)
	subjectStableID := awid.ComputeStableID(subjectPub)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)

	if err := awconfig.SaveControllerKey("aweb.ai", controllerPriv); err != nil {
		t.Fatal(err)
	}

	var registerCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+subjectStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          subjectStableID,
				"current_did_key": subjectDID,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-aweb",
				"domain":              "aweb.ai",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/aweb.ai/addresses":
			registerCalls.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["did_aw"] != subjectStableID {
				t.Fatalf("did_aw=%v want %s", body["did_aw"], subjectStableID)
			}
			if body["current_did_key"] != subjectDID {
				t.Fatalf("current_did_key=%v want %s", body["current_did_key"], subjectDID)
			}
			if body["reachability"] != "public" {
				t.Fatalf("reachability=%v want public", body["reachability"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "aweb.ai",
				"name":            "alice",
				"did_aw":          subjectStableID,
				"current_did_key": subjectDID,
				"reachability":    "public",
				"created_at":      "2026-04-20T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        subjectStableID,
		Reachability: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "assigned" {
		t.Fatalf("status=%s want assigned", out.Status)
	}
	if out.Address != "aweb.ai/alice" {
		t.Fatalf("address=%s", out.Address)
	}
	if out.DIDAW != subjectStableID {
		t.Fatalf("did_aw=%s", out.DIDAW)
	}
	if out.DIDKey != subjectDID {
		t.Fatalf("did_key=%s", out.DIDKey)
	}
	if out.Reachability != "public" {
		t.Fatalf("reachability=%s", out.Reachability)
	}
	if registerCalls.Load() != 1 {
		t.Fatalf("register calls=%d want 1", registerCalls.Load())
	}
}

func TestIDNamespaceAssignAddressIdempotentMatchingDID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	subjectPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectDID := awid.ComputeDIDKey(subjectPub)
	subjectStableID := awid.ComputeStableID(subjectPub)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("aweb.ai", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+subjectStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          subjectStableID,
				"current_did_key": subjectDID,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-aweb",
				"domain":              "aweb.ai",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/aweb.ai/addresses":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "address already exists"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "aweb.ai",
				"name":            "alice",
				"did_aw":          subjectStableID,
				"current_did_key": subjectDID,
				"reachability":    "public",
				"created_at":      "2026-04-15T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        subjectStableID,
		Reachability: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "already_assigned" {
		t.Fatalf("status=%s want already_assigned", out.Status)
	}
	if out.Address != "aweb.ai/alice" {
		t.Fatalf("address=%s", out.Address)
	}
}

func TestIDNamespaceAssignAddressConflictWithStaleAddressKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	subjectPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectDID := awid.ComputeDIDKey(subjectPub)
	subjectStableID := awid.ComputeStableID(subjectPub)
	stalePub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	staleDID := awid.ComputeDIDKey(stalePub)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("aweb.ai", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+subjectStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          subjectStableID,
				"current_did_key": subjectDID,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-aweb",
				"domain":              "aweb.ai",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/aweb.ai/addresses":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "address already exists"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "aweb.ai",
				"name":            "alice",
				"did_aw":          subjectStableID,
				"current_did_key": staleDID,
				"reachability":    "public",
				"created_at":      "2026-04-15T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        subjectStableID,
		Reachability: "public",
	})
	if err == nil {
		t.Fatal("expected error for stale address key")
	}
	if !strings.Contains(err.Error(), staleDID) || !strings.Contains(err.Error(), subjectDID) {
		t.Fatalf("error should mention stale and current did:key, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressConflictWithDifferentDID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	subjectPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectDID := awid.ComputeDIDKey(subjectPub)
	subjectStableID := awid.ComputeStableID(subjectPub)

	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherStableID := awid.ComputeStableID(otherPub)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("aweb.ai", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+subjectStableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          subjectStableID,
				"current_did_key": subjectDID,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-aweb",
				"domain":              "aweb.ai",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/aweb.ai/addresses":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "address already exists"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/aweb.ai/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "aweb.ai",
				"name":            "alice",
				"did_aw":          otherStableID,
				"current_did_key": awid.ComputeDIDKey(otherPub),
				"reachability":    "public",
				"created_at":      "2026-04-15T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        subjectStableID,
		Reachability: "public",
	})
	if err == nil {
		t.Fatal("expected error for DID mismatch")
	}
	if !strings.Contains(err.Error(), otherStableID) {
		t.Fatalf("error should mention conflicting did_aw %s, got: %v", otherStableID, err)
	}
}

func TestIDNamespaceAssignAddressTeamMembersOnlyRequiresVisibleTeamID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_REGISTRY_URL", "http://example.invalid")

	_, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        "did:aw:abc",
		Reachability: "team_members_only",
	})
	if err == nil {
		t.Fatal("expected error when reachability=team_members_only without visible-to-team-id")
	}
	if !strings.Contains(err.Error(), "visible-to-team-id") {
		t.Fatalf("error should mention visible-to-team-id, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressVisibleTeamIDOnlyValidForTeamMembersOnly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_REGISTRY_URL", "http://example.invalid")

	_, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:          "aweb.ai",
		Name:            "alice",
		DIDAW:           "did:aw:abc",
		Reachability:    "public",
		VisibleToTeamID: "some:team.example",
	})
	if err == nil {
		t.Fatal("expected error when visible-to-team-id is set without reachability=team_members_only")
	}
	if !strings.Contains(err.Error(), "visible-to-team-id") {
		t.Fatalf("error should mention visible-to-team-id, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressEmptyDIDAW(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_REGISTRY_URL", "http://example.invalid")

	_, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        "did:aw:",
		Reachability: "public",
	})
	if err == nil {
		t.Fatal("expected error for empty did:aw body")
	}
	if !strings.Contains(err.Error(), "did:aw") {
		t.Fatalf("error should mention did:aw, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressMissingControllerKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("registry should not be called: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        "did:aw:xyz",
		Reachability: "public",
	})
	if err == nil {
		t.Fatal("expected error for missing controller key")
	}
	if !strings.Contains(err.Error(), "controller key") {
		t.Fatalf("error should mention controller key, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressControllerMismatch(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	subjectPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectStableID := awid.ComputeStableID(subjectPub)

	_, localPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("aweb.ai", localPriv); err != nil {
		t.Fatal(err)
	}

	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherControllerDID := awid.ComputeDIDKey(otherPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/namespaces/aweb.ai" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-aweb",
				"domain":              "aweb.ai",
				"controller_did":      otherControllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
			return
		}
		t.Fatalf("unexpected %s %s — should not reach DID resolve or address POST", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain:       "aweb.ai",
		Name:         "alice",
		DIDAW:        subjectStableID,
		Reachability: "public",
	})
	if err == nil {
		t.Fatal("expected error for controller key mismatch")
	}
	if !strings.Contains(err.Error(), "controller") {
		t.Fatalf("error should mention controller mismatch, got: %v", err)
	}
}
