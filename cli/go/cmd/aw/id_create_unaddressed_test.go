package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
		before, contents := registry.count(), homeContents(t, root)
		_, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
		if errorCodeOf(err) != "identity_exists" || registry.count() != before {
			t.Errorf("%s: err %v after %d registrations", name, err, registry.count()-before)
		}
		if !maps.Equal(contents, homeContents(t, root)) {
			t.Errorf("%s: the refusal changed the home", name)
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

func TestAResumedCreationRefusesAFileItDidNotCreateBeforeSendingAnything(t *testing.T) {
	for name, installKey := range map[string]bool{"before its key": false, "with its key": true} {
		registry := newMappingRegistry(t)
		root := t.TempDir()
		interruptedCreation(t, root, registry.server.URL, installKey)
		if err := os.WriteFile(filepath.Join(root, "workspace.yaml"), []byte("aweb_url: https://other.example\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		contents := homeContents(t, root)
		_, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
		if errorCodeOf(err) != "identity_exists" || registry.count() != 0 {
			t.Errorf("%s: err %v after %d registrations", name, err, registry.count())
		}
		if !maps.Equal(contents, homeContents(t, root)) {
			t.Errorf("%s: the refusal changed the home", name)
		}
		if _, statErr := os.Stat(filepath.Join(root, "signing.key")); installKey == os.IsNotExist(statErr) {
			t.Errorf("%s: the key was installed or removed", name)
		}
	}
}

func TestADanglingIdentityEntryRefusesBeforeAnyRegistration(t *testing.T) {
	for name, interrupted := range map[string]bool{"fresh home": false, "interrupted creation": true} {
		registry := newMappingRegistry(t)
		root := t.TempDir()
		if interrupted {
			interruptedCreation(t, root, registry.server.URL, true)
		}
		if err := os.Symlink(filepath.Join(root, "missing-target"), filepath.Join(root, "identity.yaml")); err != nil {
			t.Fatal(err)
		}
		contents := homeContents(t, root)
		_, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
		if errorCodeOf(err) != "identity_exists" || registry.count() != 0 {
			t.Errorf("%s: err %v after %d registrations", name, err, registry.count())
		}
		if !maps.Equal(contents, homeContents(t, root)) {
			t.Errorf("%s: the refusal changed the home", name)
		}
	}
}

// The command refuses a home holding an identity before the pre-run renews
// that identity's due encryption assertion or checks for updates.
func TestNoAddressRefusesAnExistingIdentityWithoutRenewingIt(t *testing.T) {
	assertRefusalDoesNotRenew(t, "identity_exists", func(registryURL string) []string {
		return []string{"id", "create", "--no-address", "--registry", registryURL}
	})
}

func TestLocalRefusesAnExistingIdentityWithoutRenewingIt(t *testing.T) {
	assertRefusalDoesNotRenew(t, "identity_exists", func(string) []string { return []string{"id", "create", "--local"} })
}

// assertRefusalDoesNotRenew runs aw with args on a home holding a messaging
// identity whose encryption assertion is due, and wants the refusal code
// before any request or change to the home; an ordinary command on the same
// home then renews the assertion.
func assertRefusalDoesNotRenew(t *testing.T, code string, args func(registryURL string) []string) {
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	var mu sync.Mutex
	requests := []string{}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox" {
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key" {
			var assertion awid.EncryptionKeyAssertion
			_ = json.NewDecoder(r.Body).Decode(&assertion)
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_key": assertion})
			return
		}
		http.NotFound(w, r)
	}))
	writeMessagingPrincipalForTest(t, root, server.URL, "alice", did, key)
	home := filepath.Join(root, ".aw")
	installMailReadEncryptionKeyForTest(t, root, home, did, key)
	statePath := filepath.Join(home, "encryption.yaml")
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		t.Fatal(err)
	}
	record := state.ActiveRecord()
	private, err := awid.LoadX25519PrivateKey(filepath.Join(home, record.PrivateKeyPath))
	if err != nil {
		t.Fatal(err)
	}
	due, err := awid.BuildEncryptionKeyAssertion(key, did, "", private.PublicKey().Bytes(), "", time.Now().Add(-80*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := saveEncryptionAssertion(filepath.Join(home, record.AssertionPath), due); err != nil {
		t.Fatal(err)
	}
	record.ExpiresAt = due.ExpiresAt
	state.UpsertRecord(*record)
	if err := awconfig.SaveEncryptionKeyStateTo(statePath, state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	before := homeContents(t, home)
	command := exec.CommandContext(ctx, bin, append([]string{"--json", "--identity-home", home}, args(server.URL)...)...)
	command.Dir, command.Env = root, testCommandEnv(root)
	out, runErr := command.CombinedOutput()
	mu.Lock()
	sent := append([]string(nil), requests...)
	mu.Unlock()
	if runErr == nil || !strings.Contains(string(out), code) || len(sent) != 0 {
		t.Fatalf("want %s before any request: error=%v requests=%v output=%s", code, runErr, sent, out)
	}
	if after := homeContents(t, home); !maps.Equal(before, after) {
		t.Fatalf("the refused creation changed the home: before %v after %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	// The same home's due assertion is renewed by an ordinary command.
	inbox := exec.CommandContext(ctx, bin, "--identity-home", home, "mail", "inbox")
	inbox.Dir, inbox.Env = root, testCommandEnv(root)
	if out, err := inbox.CombinedOutput(); err != nil {
		t.Fatalf("mail inbox: %v %s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(requests, http.MethodPut+" /v1/agents/me/encryption-key") {
		t.Fatalf("an ordinary command did not renew the due assertion: %v", requests)
	}
}

// homeContents maps each file under home to its bytes, and each symbolic
// link to its target.
func homeContents(t *testing.T, home string) map[string]string {
	t.Helper()
	contents := map[string]string{}
	err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			contents[path] = "-> " + target
			return err
		}
		data, err := os.ReadFile(path)
		contents[path] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
