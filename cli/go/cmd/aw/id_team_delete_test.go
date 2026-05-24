package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestTeamDeleteHappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-acme",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com/teams/backend":
			verifyRegistrySignatureForTest(t, r, controllerPub, map[string]string{
				"domain":    "acme.com",
				"operation": "delete_team",
				"team_name": "backend",
			})
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeTeamDelete(context.Background(), teamDeleteOptions{
		Domain: "acme.com",
		Team:   "backend",
		Reason: "retry clean byot setup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" {
		t.Fatalf("status=%s want deleted", out.Status)
	}
	if out.TeamID != "backend:acme.com" {
		t.Fatalf("team_id=%s", out.TeamID)
	}
	if out.ControllerDID != controllerDID {
		t.Fatalf("controller=%s want %s", out.ControllerDID, controllerDID)
	}
	if gotBody["reason"] != "retry clean byot setup" {
		t.Fatalf("reason=%v", gotBody["reason"])
	}
}

func TestTeamDeleteRejectsFullTeamID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := executeTeamDelete(context.Background(), teamDeleteOptions{
		Domain: "acme.com",
		Team:   "backend:acme.com",
	})
	if err == nil || !strings.Contains(err.Error(), "not a full team id") {
		t.Fatalf("err=%v", err)
	}
}

func TestTeamDeleteActiveCertificatesMessage(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-acme",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com/teams/backend":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Team has active certificates"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeTeamDelete(context.Background(), teamDeleteOptions{
		Domain: "acme.com",
		Team:   "backend",
	})
	if err == nil || !strings.Contains(err.Error(), "remove-member") {
		t.Fatalf("err=%v", err)
	}
}
