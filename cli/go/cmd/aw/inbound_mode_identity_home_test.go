package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// inbound-mode acts from an external identity home (Juan's item 5; Athena
// daebdec3): the custody root reads and sets the mode, signed with its own key
// and never the CWD workspace's; a grant home reaches the server and gets the
// server's grant refusal unchanged.
func TestInboundModeActsFromAnExternalIdentityHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	_, custodyKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	custodyDID := awid.ComputeDIDKey(custodyKey.Public().(ed25519.PublicKey))
	_, decoyKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	decoyDID := awid.ComputeDIDKey(decoyKey.Public().(ed25519.PublicKey))

	const grantRefusal = "grant principals cannot use this route"
	var mu sync.Mutex
	var calls []string
	mode := "team_and_contacts"
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		auth := strings.Fields(r.Header.Get("Authorization"))
		signer := ""
		if len(auth) == 3 {
			signer = auth[1]
		}
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+signer)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/agents/me/inbound-mode" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"detail":"Not found"}`)
			return
		}
		if signer != custodyDID {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"detail":"`+grantRefusal+`"}`)
			return
		}
		if r.Method == http.MethodPatch {
			var req map[string]string
			_ = json.Unmarshal(body, &req)
			mode = req["inbound_mode"]
		}
		_, _ = io.WriteString(w, `{"agent_id":"a1","team_id":"default:acme.aweb.ai","alias":"gandalf","identity_scope":"global","inbound_mode":"`+mode+`","configurable":true}`)
	}))

	custody := filepath.Join(root, "custody")
	writeSelectionFixtureForTest(t, custody, testSelectionFixture{AwebURL: server.URL, TeamID: "default:acme.aweb.ai", Alias: "gandalf", DID: custodyDID, StableID: awid.ComputeStableID(custodyKey.Public().(ed25519.PublicKey)), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: custodyKey})
	// The working directory is a different agent's workspace: the signer must
	// come from --identity-home, never from here.
	decoy := filepath.Join(root, "decoy")
	writeSelectionFixtureForTest(t, decoy, testSelectionFixture{AwebURL: server.URL, TeamID: "default:acme.aweb.ai", Alias: "decoy", DID: decoyDID, StableID: awid.ComputeStableID(decoyKey.Public().(ed25519.PublicKey)), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: decoyKey})
	grant := filepath.Join(root, "grant")
	writeGrantHomeForTest(t, grant, server.URL)

	run := func(t *testing.T, env []string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = decoy
		cmd.Env = append(testCommandEnv(filepath.Join(root, "home")), append([]string{"AWEB_IDENTITY_HOME=", "AWEB_URL=", "AW_TRACE=", "AW_NO_UPDATE_CHECK=1"}, env...)...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		code := 0
		if err := cmd.Run(); err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = exitErr.ExitCode()
		}
		return out.String(), code
	}

	custodyHome := filepath.Join(custody, ".aw")
	for _, byFlag := range []bool{true, false} {
		prefix, env := []string{"--identity-home", custodyHome}, []string(nil)
		if !byFlag {
			prefix, env = nil, []string{"AWEB_IDENTITY_HOME=" + custodyHome}
		}
		mode = "team_and_contacts"
		if out, code := run(t, env, append(prefix, "inbound-mode", "--json")...); code != 0 || !strings.Contains(out, `"inbound_mode": "team_and_contacts"`) {
			t.Fatalf("read from the custody root (flag=%v): exit %d\n%s", byFlag, code, out)
		}
		if out, code := run(t, env, append(prefix, "inbound-mode", "open", "--json")...); code != 0 || !strings.Contains(out, `"inbound_mode": "open"`) {
			t.Fatalf("set from the custody root (flag=%v): exit %d\n%s", byFlag, code, out)
		}
	}

	out, code := run(t, nil, "--identity-home", grant, "inbound-mode", "open", "--json")
	if code == 0 || !strings.Contains(out, grantRefusal) {
		t.Fatalf("grant home: exit %d, want the server's refusal\n%s", code, out)
	}

	mu.Lock()
	defer mu.Unlock()
	reachedFromGrant := false
	for _, call := range calls {
		if strings.HasSuffix(call, " "+decoyDID) {
			t.Fatalf("a request was signed by the CWD workspace's key: %v", calls)
		}
		if strings.HasPrefix(call, "PATCH /v1/agents/me/inbound-mode") && !strings.HasSuffix(call, " "+custodyDID) {
			reachedFromGrant = true
		}
	}
	if !reachedFromGrant {
		t.Fatalf("the grant home's request never reached the server: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("wrote instance identity: %v", err)
	}
}
