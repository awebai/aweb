package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIdentitySelectionAcrossCommandGroups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	keys := map[string]ed25519.PublicKey{}
	dids := map[string]string{}
	private := map[string]ed25519.PrivateKey{}
	for _, name := range []string{"cwd", "environment", "flag"} {
		pub, key, _ := ed25519.GenerateKey(nil)
		did := awid.ComputeDIDKey(pub)
		keys[did], dids[name], private[name] = pub, did, key
	}
	type call struct{ path, did string }
	var mu sync.Mutex
	var calls []call
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.Fields(r.Header.Get("Authorization"))
		if len(auth) != 3 {
			http.NotFound(w, r)
			return
		}
		pub := keys[auth[1]]
		body, _ := io.ReadAll(r.Body)
		payload := requestSigningPayloadForTest(t, r, body)
		sig, _ := base64.RawStdEncoding.DecodeString(auth[2])
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, payload, sig) {
			t.Error("request signature does not verify under its declared principal")
			w.WriteHeader(500)
			return
		}
		mu.Lock()
		calls = append(calls, call{r.URL.Path, auth[1]})
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"detail":{"code":"fixture_authority_refusal"}}`)
	}))
	for _, name := range []string{"cwd", "environment", "flag"} {
		writeSelectionFixtureForTest(t, filepath.Join(root, name), testSelectionFixture{AwebURL: server.URL, RegistryURL: server.URL, TeamID: name + ":example.test", Alias: name, DID: dids[name], StableID: awid.ComputeStableID(keys[dids[name]]), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: private[name]})
	}
	cwd := filepath.Join(root, "cwd")
	for _, mode := range []string{"environment", "flag", "cwd"} {
		for _, command := range []struct {
			name, path string
			args       []string
		}{
			{"mail", "/v1/messages/inbox", []string{"mail", "inbox", "--json"}},
			{"chat", "/v1/chat/pending", []string{"chat", "pending", "--json"}},
			{"invite", "/api/v1/spawn/create-invite", []string{"team", "invite", "--json"}},
			{"contacts", "/v1/contacts", []string{"contacts", "list", "--json"}},
			{"inbound-mode", "/v1/agents/me/inbound-mode", []string{"inbound-mode", "--json"}},
			{"task", "/v1/tasks", []string{"task", "list", "--json"}},
			{"id", "/v1/identity-fixture", []string{"id", "request", "GET", server.URL + "/v1/identity-fixture", "--team-auth", "--json"}},
			{"workspace", "/v1/workspaces/team", []string{"workspace", "status", "--json"}},
		} {
			t.Run(mode+"/"+command.name, func(t *testing.T) {
				before := snapshotJoinFiles(t, cwd)
				mu.Lock()
				calls = nil
				mu.Unlock()
				args := append([]string{}, command.args...)
				env := append(testCommandEnv(filepath.Join(root, "user-home")), "USERPROFILE="+filepath.Join(root, "user-home"), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWEB_API_KEY=", "AWID_REGISTRY_URL=", "AW_NO_UPDATE_CHECK=1")
				if mode != "cwd" {
					env = append(env, "AWEB_IDENTITY_HOME="+filepath.Join(root, "environment", ".aw"))
				}
				if mode == "flag" {
					args = append([]string{"--identity-home", filepath.Join(root, "flag", ".aw")}, args...)
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir, cmd.Env = cwd, env
				out, _ := cmd.CombinedOutput()
				mu.Lock()
				observed := append([]call{}, calls...)
				mu.Unlock()
				found := false
				for _, c := range observed {
					if c.did != dids[mode] {
						t.Fatalf("wrong acting key: %s want %s; calls=%v", c.did, dids[mode], observed)
					}
					if c.path == command.path {
						found = true
					}
				}
				if !found {
					t.Fatalf("command never reached its authority boundary %s: calls=%v\n%s", command.path, observed, out)
				}
				if mode != "cwd" && !reflect.DeepEqual(before, snapshotJoinFiles(t, cwd)) {
					t.Fatal("external principal changed CWD identity files")
				}
			})
		}
	}
}

func TestSelectedIdentityNeverFallsBackAndInitPreservesInheritedIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	_, key, _ := ed25519.GenerateKey(nil)
	cwd := filepath.Join(root, "cwd")
	writeSelectionFixtureForTest(t, cwd, testSelectionFixture{AwebURL: "http://127.0.0.1:1", TeamID: "decoy:example.test", Alias: "decoy", DID: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: key})
	before := snapshotJoinFiles(t, cwd)
	for _, name := range []string{"empty", "missing"} {
		selected := filepath.Join(root, name)
		if name == "empty" {
			if err := os.Mkdir(selected, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, args := range [][]string{
			{"id", "show", "--json"},
			{"team", "invite", "--team-id", "backend:acme.com", "--json"},
			{"id", "team", "create", "--team", "new", "--namespace", "acme.com", "--json"},
			{"id", "create", "--name", "new", "--domain", "acme.com", "--skip-dns-verify", "--json"},
		} {
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir, cmd.Env = cwd, append(testCommandEnv(filepath.Join(root, "user-home")), "AWEB_IDENTITY_HOME="+selected, "AW_NO_UPDATE_CHECK=1")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), selected) {
				t.Errorf("selected %s must fail with folder named for %v: %v\n%s", name, args, err, out)
			}
		}
	}
	fresh := filepath.Join(root, "new-subfolder")
	if err := os.Mkdir(fresh, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "init", "--new-account", "--username", "fixture", "--name", "fixture")
	cmd.Dir, cmd.Env = fresh, append(testCommandEnv(filepath.Join(root, "user-home")), "AWEB_IDENTITY_HOME="+filepath.Join(cwd, ".aw"), "AW_NO_UPDATE_CHECK=1")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("init extended inherited identity: %s", out)
	}
	if !reflect.DeepEqual(before, snapshotJoinFiles(t, cwd)) {
		t.Fatal("init or selected-home error changed inherited/decoy identity")
	}
	if _, err := os.Lstat(filepath.Join(fresh, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("init wrote implicit instance identity: %v", err)
	}
}

// The shipped SDK uses the legacy certificate envelope; explicit id request
// can use request-bound v2. Verify the actual signed shape in either case.
func requestSigningPayloadForTest(t *testing.T, r *http.Request, body []byte) []byte {
	t.Helper()
	if encoded := r.Header.Get("X-AWEB-Signed-Payload"); encoded != "" {
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("signed payload header: %v", err)
		}
		return payload
	}
	hash := sha256.Sum256(body)
	fields := map[string]string{"body_sha256": hex.EncodeToString(hash[:]), "timestamp": r.Header.Get("X-AWEB-Timestamp")}
	if encoded := r.Header.Get("X-AWID-Team-Certificate"); encoded != "" {
		cert, err := awid.DecodeTeamCertificateHeader(encoded)
		if err != nil {
			t.Errorf("team certificate header: %v", err)
			return nil
		}
		fields["team_id"] = cert.Team
	} else {
		fields["did_aw"] = r.Header.Get("X-AWEB-DID-AW")
	}
	canonical, err := awid.CanonicalJSONValue(fields)
	if err != nil {
		t.Errorf("canonical request: %v", err)
	}
	return []byte(canonical)
}

func writeStandaloneSelectedIdentityForTest(t *testing.T, root string) {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(root, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, "identity.yaml"), &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(pub), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal}); err != nil {
		t.Fatal(err)
	}
}
