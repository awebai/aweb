package main

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// The registry boundary is HTTP; every claim uses the actual persisted private
// key and production signatures. A lost result must not mint another identity.
func TestIDCreatePersistsKeyBeforeClaimAndResumesSameIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	pub, controller, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(pub)
	if err := awconfig.SaveControllerKey("acme.com", controller); err != nil {
		t.Fatal(err)
	}
	claims := 0
	var claimedDID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com":
			json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": controllerDID})
		case "/v1/namespaces/acme.com/addresses/claims":
			claims++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			key, err := awid.LoadSigningKey(filepath.Join(root, ".aw", "signing.key"))
			if err != nil {
				t.Errorf("registry claim preceded durable signing key: %v", err)
			} else if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != body["current_did_key"] {
				t.Error("claim used another key")
			}
			if claims == 1 {
				claimedDID, _ = body["current_did_key"].(string)
				http.Error(w, "uncertain claim result", 503)
				return
			}
			if body["current_did_key"] != claimedDID {
				t.Error("retry minted another identity")
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "claimed", "current_did_key": body["current_did_key"], "did_aw": body["did_aw"]})
		default:
			if r.Method == http.MethodPost {
				w.WriteHeader(201)
				return
			}
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	opts := idCreateOptions{Name: "alice", Domain: "acme.com", RegistryURL: server.URL, SkipDNSVerify: true, TXTResolver: staticTXTResolver{"_awid.acme.com": {idCreateDNSRecordValue(controllerDID, "")}}}
	if _, err := executeIDCreate(root, opts); err == nil {
		t.Fatal("lost result reported success")
	} else if claims == 0 {
		t.Fatalf("failed before the registry boundary: %v", err)
	}
	keyPath := filepath.Join(root, ".aw", "signing.key")
	original, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("lost original key: %v", err)
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions: %v %v", info, err)
	}
	if info, err := os.Stat(filepath.Join(root, ".aw", "id-create.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("recovery permissions: %v %v", info, err)
	}
	before := claims
	wrong := opts
	wrong.Name = "bob"
	if _, err := executeIDCreate(root, wrong); err == nil || claims != before {
		t.Fatalf("selection changed on retry: claims=%d err=%v", claims, err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDCreate(root, opts); err == nil || claims != before {
		t.Fatalf("missing original key was replaced: claims=%d err=%v", claims, err)
	}
	if err := os.WriteFile(keyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := executeIDCreate(root, opts)
	if err != nil || out.DIDKey != claimedDID {
		t.Fatalf("same-key resume: out=%+v err=%v", out, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw", "id-create.json")); !os.IsNotExist(err) {
		t.Fatalf("success retained recovery: %v", err)
	}
}
