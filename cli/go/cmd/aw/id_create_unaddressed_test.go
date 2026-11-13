package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// mappingRegistry is a registry of did:aw mappings: a registration of a new
// did:aw records its first key, a second one answers 409, and reads answer
// the recorded key unless readKey overrides it.
type mappingRegistry struct {
	mu            sync.Mutex
	server        *httptest.Server
	keys          map[string]string
	registrations int
	readKey       string
}

func newMappingRegistry(t *testing.T) *mappingRegistry {
	t.Helper()
	r := &mappingRegistry{keys: map[string]string{}}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/v1/did":
			var body struct {
				DIDAW     string `json:"did_aw"`
				NewDIDKey string `json:"new_did_key"`
			}
			_ = json.NewDecoder(req.Body).Decode(&body)
			if _, taken := r.keys[body.DIDAW]; taken {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"detail":"already registered"}`))
				return
			}
			r.registrations++
			r.keys[body.DIDAW] = body.NewDIDKey
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/v1/did/"):
			id := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/did/"), "/")[0]
			key, ok := r.keys[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"detail":"not found"}`))
				return
			}
			if r.readKey != "" {
				key = r.readKey
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": id, "current_did_key": key})
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *mappingRegistry) client(t *testing.T) *awid.RegistryClient {
	t.Helper()
	client, err := newConfiguredRegistryClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.TrustRegistryOrigin(r.server.URL); err != nil {
		t.Fatal(err)
	}
	return client
}

func (r *mappingRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registrations
}

func unaddressedRequest(t *testing.T, registry *mappingRegistry, root string) unaddressedCreate {
	return unaddressedCreate{Root: root, RegistryURL: registry.server.URL, Registry: registry.client(t)}
}

// interruptedCreation is the private state a creation killed after writing
// it left behind: its marker, and its signing key when installKey.
// It holds no key material; the key, once installed, is the creation's.
func interruptedCreation(t *testing.T, root, registryURL string, installKey bool) ed25519.PrivateKey {
	t.Helper()
	raw, _ := json.Marshal(unaddressedCreationState{Version: 1, RegistryURL: registryURL})
	if err := os.WriteFile(filepath.Join(root, unaddressedStateFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if !installKey {
		return nil
	}
	_, key, _ := ed25519.GenerateKey(nil)
	if err := awid.SaveSigningKey(filepath.Join(root, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	return key
}

func unaddressedDIDs(key ed25519.PrivateKey) (string, string) {
	public := key.Public().(ed25519.PublicKey)
	return awid.ComputeDIDKey(public), awid.ComputeStableID(public)
}

func assertCompleteIdentity(t *testing.T, root, registryURL string, result map[string]any) {
	t.Helper()
	key, err := awid.LoadSigningKey(filepath.Join(root, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(root, "signing.key")); info.Mode().Perm() != 0o600 {
		t.Fatalf("signing key mode %v", info.Mode().Perm())
	}
	didKey, stableID := unaddressedDIDs(key)
	if result["did_key"] != didKey || result["did_aw"] != stableID || result["registry_url"] != registryURL {
		t.Fatalf("result %v for %s %s", result, didKey, stableID)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(root, "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != didKey || identity.StableID != stableID || identity.Address != "" || identity.Custody != awid.CustodySelf ||
		identity.IdentityScope != awid.IdentityModeGlobal || identity.RegistryURL != registryURL || identity.RegistryStatus != "registered" {
		t.Fatalf("identity %+v", identity)
	}
	if _, err := os.Stat(filepath.Join(root, unaddressedStateFile)); !os.IsNotExist(err) {
		t.Fatal("the creation state remains after completion")
	}
}

func TestAnUnaddressedIdentityIsRegisteredWithItsOwnKeyAndWrittenWithNoAddress(t *testing.T) {
	registry := newMappingRegistry(t)
	root := t.TempDir()
	result, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
	if err != nil {
		t.Fatal(err)
	}
	assertCompleteIdentity(t, root, registry.server.URL, result)
	if result["status"] != "created" || registry.count() != 1 {
		t.Fatalf("result %v after %d registrations", result, registry.count())
	}
}

func TestAKilledCreationResumesWithItsOriginalKey(t *testing.T) {
	for name, tc := range map[string]struct {
		installKey, registered bool
	}{
		"before its key was installed": {false, false},
		"before it registered":         {true, false},
		"after it registered":          {true, true},
	} {
		registry := newMappingRegistry(t)
		root := t.TempDir()
		key := interruptedCreation(t, root, registry.server.URL, tc.installKey)
		if tc.registered {
			didKey, stableID := unaddressedDIDs(key)
			registry.keys[stableID] = didKey
		}
		result, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertCompleteIdentity(t, root, registry.server.URL, result)
		if result["status"] != "resumed" {
			t.Errorf("%s: result %v", name, result)
		}
		// An installed key is the creation's own; never replaced.
		if key != nil {
			if didKey, _ := unaddressedDIDs(key); result["did_key"] != didKey {
				t.Errorf("%s: the installed key was replaced: %v", name, result)
			}
		}
		if want := map[bool]int{false: 1, true: 0}[tc.registered]; registry.count() != want {
			t.Errorf("%s: %d registrations, want %d", name, registry.count(), want)
		}
	}
}

func TestAHomeHoldingAnotherOrACompleteIdentityRefusesAndSendsNothing(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, root, registryURL string){
		"a complete identity": func(t *testing.T, root, registryURL string) {
			registry := newMappingRegistry(t)
			if _, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root)); err != nil {
				t.Fatal(err)
			}
		},
		"a complete identity killed before its state was removed": func(t *testing.T, root, registryURL string) {
			registry := newMappingRegistry(t)
			if _, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root)); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(unaddressedCreationState{Version: 1, RegistryURL: registryURL})
			_ = os.WriteFile(filepath.Join(root, unaddressedStateFile), raw, 0o600)
		},
		"a key with no creation state": func(t *testing.T, root, _ string) {
			_, key, _ := ed25519.GenerateKey(nil)
			_ = awid.SaveSigningKey(filepath.Join(root, "signing.key"), key)
		},
		"another file": func(t *testing.T, root, _ string) {
			_ = os.WriteFile(filepath.Join(root, "teams.yaml"), []byte("{}"), 0o600)
		},
		"a creation at another registry": func(t *testing.T, root, _ string) {
			interruptedCreation(t, root, "https://other-registry.example", true)
		},
	} {
		registry := newMappingRegistry(t)
		root := t.TempDir()
		prepare(t, root, registry.server.URL)
		before := registry.count()
		_, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
		if errorCodeOf(err) != "identity_exists" || registry.count() != before {
			t.Errorf("%s: err %v after %d registrations", name, err, registry.count()-before)
		}
	}
}

func TestAMappingTheRegistryDoesNotHoldForThisKeyCompletesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		registeredToOther bool
		readKey           string
	}{
		"already registered to another key": {registeredToOther: true},
		"read back with another key":        {readKey: "did:key:z6MkotherXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
	} {
		registry := newMappingRegistry(t)
		root := t.TempDir()
		key := interruptedCreation(t, root, registry.server.URL, true)
		_, stableID := unaddressedDIDs(key)
		if tc.registeredToOther {
			registry.keys[stableID] = "did:key:z6MkotherXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		}
		registry.readKey = tc.readKey
		if _, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root)); err == nil {
			t.Errorf("%s: completed", name)
		}
		if _, err := os.Stat(filepath.Join(root, "identity.yaml")); !os.IsNotExist(err) {
			t.Errorf("%s: identity written", name)
		}
		if info, err := os.Stat(filepath.Join(root, unaddressedStateFile)); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: the creation state was dropped or is not private: %v", name, err)
		}
	}
}

func TestNoAddressNeedsAnExplicitHomeAndRegistryAndNoAddressFlags(t *testing.T) {
	for name, tc := range map[string]struct {
		set      map[string]string
		explicit bool
		ok       bool
	}{
		"explicit home and registry": {map[string]string{"registry": "https://registry.example"}, true, true},
		"no registry":                {map[string]string{}, true, false},
		"implicit home":              {map[string]string{"registry": "https://registry.example"}, false, false},
		"with --name":                {map[string]string{"registry": "https://registry.example", "name": "root"}, true, false},
		"with --domain":              {map[string]string{"registry": "https://registry.example", "domain": "example.com"}, true, false},
		"with --org":                 {map[string]string{"registry": "https://registry.example", "org": "acme"}, true, false},
		"with --human-parent":        {map[string]string{"registry": "https://registry.example", "human-parent": "did:aw:x"}, true, false},
		"with --root-parent":         {map[string]string{"registry": "https://registry.example", "root-parent": "true"}, true, false},
		"with --skip-dns-verify":     {map[string]string{"registry": "https://registry.example", "skip-dns-verify": "true"}, true, false},
	} {
		cmd := &cobra.Command{}
		flags := cmd.Flags()
		for _, flag := range []string{"registry", "name", "domain", "org", "human-parent", "team-id", "inbound-mode", "owner-identity-home"} {
			flags.String(flag, "", "")
		}
		flags.Bool("root-parent", false, "")
		flags.Bool("skip-dns-verify", false, "")
		for flag, value := range tc.set {
			if err := flags.Set(flag, value); err != nil {
				t.Fatal(err)
			}
		}
		err := unaddressedFlagsRefusal(cmd, tc.explicit)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
}
