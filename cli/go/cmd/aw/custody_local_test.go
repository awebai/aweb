package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestCustodyStartupLocalWorkspaceWithoutIdentityFile(t *testing.T) {
	resetGrantCommandGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	setGrantTestEnv(t, root)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/identity-grants/00000000-0000-0000-0000-000000000000/status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "grant_not_found", "contract": "identity-grant-status.v1"})
	}))
	defer server.Close()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	writeLocalTeamSignedRequestWorkspaceForTest(t, root, server.URL, "backend:demo", "resident", did, key)
	if _, err := os.Stat(filepath.Join(root, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("fixture must omit identity.yaml: %v", err)
	}
	home, err := awconfig.ResolveIdentityHome(root, "")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatalf("local custody startup: %v", err)
	}
	if svc.identity.DID != did || svc.identity.StableID != "" || svc.identity.IdentityScope != awid.IdentityModeLocal {
		t.Fatalf("wrong resident identity: %+v", svc.identity)
	}
	status := svc.status(context.Background(), "running", nil)
	if status.Keys["signing_ready"] != true || calls != 1 {
		t.Fatalf("local readiness=%+v, probe calls=%d", status, calls)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("startup must not create identity.yaml: %v", err)
	}
}
