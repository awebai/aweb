package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIDNamespaceDeleteHappyPath(t *testing.T) {
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
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com":
			verifyRegistrySignatureForTest(t, r, controllerPub, map[string]string{
				"domain":    "acme.com",
				"operation": "delete_namespace",
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

	out, err := executeIDNamespaceDelete(context.Background(), idNamespaceDeleteOptions{
		Domain: "acme.com",
		Reason: "fresh setup retry",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" {
		t.Fatalf("status=%s want deleted", out.Status)
	}
	if out.Domain != "acme.com" {
		t.Fatalf("domain=%s", out.Domain)
	}
	if out.ControllerDID != controllerDID {
		t.Fatalf("controller=%s want %s", out.ControllerDID, controllerDID)
	}
	if gotBody["reason"] != "fresh setup retry" {
		t.Fatalf("reason=%v", gotBody["reason"])
	}
}

func TestIDNamespaceDeleteActiveCertificatesMessage(t *testing.T) {
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
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Namespace has active certificates"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceDelete(context.Background(), idNamespaceDeleteOptions{
		Domain: "acme.com",
	})
	if err == nil || !strings.Contains(err.Error(), "remove-member") {
		t.Fatalf("err=%v", err)
	}
}

func TestIDNamespaceDeletePurgeLocalMovesControllerAndTeamKeys(t *testing.T) {
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
	metaPath, err := awconfig.ControllerMetaPath("acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte("domain: acme.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, teamPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("acme.com", "default", teamPriv); err != nil {
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
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeIDNamespaceDelete(context.Background(), idNamespaceDeleteOptions{
		Domain:     "acme.com",
		PurgeLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.LocalBackupDir == "" {
		t.Fatal("expected local backup dir")
	}
	stateDir, err := awconfig.DefaultUserStateDir()
	if err != nil {
		t.Fatal(err)
	}
	wantBackupRoot := filepath.Join(stateDir, "deregister-backups") + string(filepath.Separator)
	if !strings.HasPrefix(out.LocalBackupDir, wantBackupRoot) {
		t.Fatalf("backup dir %s outside durable aw state backup root %s", out.LocalBackupDir, wantBackupRoot)
	}
	for _, path := range out.MovedLocalPaths {
		if !strings.HasPrefix(path, out.LocalBackupDir+string(filepath.Separator)) {
			t.Fatalf("moved path %s outside backup dir %s", path, out.LocalBackupDir)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing moved path %s: %v", path, err)
		}
	}
	keyPath, err := awconfig.ControllerKeyPath("acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("controller key still present or unexpected err: %v", err)
	}
	teamKeysRoot, err := awconfig.DefaultTeamKeysDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(teamKeysRoot, "acme.com")); !os.IsNotExist(err) {
		t.Fatalf("team keys dir still present or unexpected err: %v", err)
	}
}
