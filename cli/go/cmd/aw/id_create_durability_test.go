package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
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
	if _, err := executeIDCreate(root, wrong); err == nil || claims != before || !strings.Contains(err.Error(), "--name") || !strings.Contains(err.Error(), "--name alice") {
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

func TestIDCreateClearsFirstDefinitiveRefusal(t *testing.T) {
	for _, write := range []string{"namespace", "address"} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusUnprocessableEntity} {
			t.Run(fmt.Sprintf("%s/%d", write, status), func(t *testing.T) {
				refuseNamespace := write == "namespace"
				root, opts, calls := standaloneCreateRefusalFixture(t, !refuseNamespace, status, refuseNamespace)
				if _, err := executeIDCreate(root, opts); err == nil {
					t.Fatal("first write unexpectedly succeeded")
				} else if retainUnfinishedProvisioningIdentity(err) {
					t.Fatalf("definitive first refusal was retained: %v", err)
				}
				for _, name := range []string{"id-create.json", "signing.key", "identity.yaml"} {
					if _, err := os.Stat(filepath.Join(root, ".aw", name)); !os.IsNotExist(err) {
						t.Fatalf("refused attempt left %s: %v", name, err)
					}
				}
				opts.Name = "bob"
				created, err := executeIDCreate(root, opts)
				wantClaimCalls := int32(2)
				if refuseNamespace {
					wantClaimCalls = 1
				}
				if err != nil || created.Address != "acme.test/bob" || calls.Load() != wantClaimCalls {
					t.Fatalf("new selection: %+v, claim calls=%d, err=%v", created, calls.Load(), err)
				}
				if _, err := os.Stat(filepath.Join(root, ".aw", "id-create.json")); !os.IsNotExist(err) {
					t.Fatalf("successful creation left an intent: %v", err)
				}
			})
		}
	}
}

func TestIDCreateKeepsPartiallyAcceptedIntent(t *testing.T) {
	root, opts, calls := standaloneCreateRefusalFixture(t, false, http.StatusConflict, false)
	_, err := executeIDCreate(root, opts)
	if err == nil || !strings.Contains(err.Error(), "namespace registration") || !strings.Contains(err.Error(), "--name alice") {
		t.Fatalf("partial acceptance did not name the registry effect and original command: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw", "id-create.json")); err != nil {
		t.Fatalf("partial acceptance lost the intent: %v", err)
	}
	changed := opts
	changed.Name = "bob"
	changed.RegistryURL = "https://other-registry.example.test"
	changed.RootParent = true
	_, err = executeIDCreate(root, changed)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("changed retry: claim calls=%d, err=%v", calls.Load(), err)
	}
	for _, want := range []string{"--name", "--registry", "--root-parent", "namespace registration", "--name alice"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("changed retry missing %q: %v", want, err)
		}
	}
	if !retainUnfinishedProvisioningIdentity(err) {
		t.Fatalf("partial retry was not retained: %v", err)
	}
	key, err := awid.LoadSigningKey(filepath.Join(root, ".aw", "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := executeIDCreate(root, opts)
	if err != nil || out.DIDKey != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) || calls.Load() != 2 {
		t.Fatalf("exact partial retry: out=%+v, claim calls=%d, err=%v", out, calls.Load(), err)
	}
}

func TestIDCreateFinishesInterruptedRefusalCleanup(t *testing.T) {
	root, opts, calls := standaloneCreateRefusalFixture(t, true, 0, false)
	prepared, err := prepareIDCreatePlan(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistStandaloneCreate(prepared, opts); err != nil {
		t.Fatal(err)
	}
	prepared.Recovery.Progress.Started = true
	prepared.Recovery.Progress.Refused = true
	if err := prepared.Recovery.write(); err != nil {
		t.Fatal(err)
	}
	// The first command was interrupted after deleting its unused key.
	if err := os.Remove(prepared.Plan.SigningKeyPath); err != nil {
		t.Fatal(err)
	}
	opts.Name = "bob"
	out, err := executeIDCreate(root, opts)
	if err != nil || calls.Load() != 1 || out.Address != "acme.test/bob" || out.DIDKey == prepared.Plan.DIDKey {
		t.Fatalf("selection after interrupted cleanup: out=%+v, claim calls=%d, err=%v", out, calls.Load(), err)
	}
	if _, err := os.Stat(standaloneCreateRecoveryPath(prepared.Plan.IdentityPath)); !os.IsNotExist(err) {
		t.Fatalf("successful creation left an intent: %v", err)
	}
}

func standaloneCreateRefusalFixture(t *testing.T, namespaceExists bool, firstStatus int, refuseNamespace bool) (string, idCreateOptions, *atomic.Int32) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	pub, controller, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const domain = "acme.test"
	controllerDID := awid.ComputeDIDKey(pub)
	if err := awconfig.SaveControllerKey(domain, controller); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var namespacePresent, namespaceRefused atomic.Bool
	namespacePresent.Store(namespaceExists)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+domain:
			if !namespacePresent.Load() {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "controller_did": controllerDID})
		case !namespacePresent.Load() && r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if refuseNamespace && namespaceRefused.CompareAndSwap(false, true) {
				http.Error(w, "namespace registration refused", firstStatus)
				return
			}
			namespacePresent.Store(true)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "controller_did": controllerDID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/"+domain+"/addresses/claims":
			claim := calls.Add(1)
			var body struct {
				Name   string `json:"address_name"`
				DIDKey string `json:"current_did_key"`
				DIDAW  string `json:"did_aw"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				http.Error(w, "invalid fixture claim", http.StatusBadRequest)
				return
			}
			if !refuseNamespace && firstStatus != 0 && claim == 1 {
				w.WriteHeader(firstStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]string{
					"code": awid.AtomicAddressClaimCodeAddressTakenDifferentOwner, "message": "definitive first refusal",
				}})
				return
			}
			wantName := "bob"
			if !namespaceExists && !refuseNamespace {
				wantName = "alice"
			}
			if body.Name != wantName {
				t.Errorf("selection claimed %q, want %q", body.Name, wantName)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "claimed", "current_did_key": body.DIDKey, "did_aw": body.DIDAW})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		default:
			t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	opts := idCreateOptions{Name: "alice", Domain: domain, RegistryURL: server.URL, SkipDNSVerify: true}
	return root, opts, &calls
}
