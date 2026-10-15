package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func TestAgentStatusProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	var vector struct {
		Seed  string `json:"signing_seed_hex"`
		DID   string `json:"publisher_did_key"`
		Valid []struct {
			Name      string          `json:"name"`
			Document  json.RawMessage `json:"document"`
			Payload   string          `json:"signed_payload"`
			Signature string          `json:"signature"`
		} `json:"valid"`
	}
	raw, err := os.ReadFile("../../../../docs/vectors/agent-status-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, env []string, stdin []byte, args ...string) (map[string]any, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = root
		cmd.Env = append(testCommandEnv(filepath.Join(root, "home")), append([]string{"AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1", "AW_AGENT_STATUS_TEST_SEED_HEX="}, env...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		e := cmd.Run()
		code := 0
		if e != nil {
			if ee, ok := e.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		var result map[string]any
		decoder := json.NewDecoder(&stdout)
		if e := decoder.Decode(&result); e != nil {
			t.Fatalf("not one JSON object: %v; stdout %s stderr %s", e, stdout.String(), stderr.String())
		}
		var extra any
		if e := decoder.Decode(&extra); e != io.EOF {
			t.Fatalf("extra stdout: %v %v", extra, e)
		}
		return result, code
	}
	for _, v := range vector.Valid {
		t.Run("vector/"+v.Name, func(t *testing.T) {
			out, code := run(t, []string{"AW_AGENT_STATUS_TEST_SEED_HEX=" + vector.Seed}, v.Document, "status", "publish", "--alias", "subject", "--document", "-", "--print-signed")
			if code != 0 || out["signed_payload"] != v.Payload || out["signature"] != v.Signature || len(out) != 2 {
				t.Fatalf("vector mismatch: exit%d %#v", code, out)
			}
		})
	}
	wrong := bytes.Replace(vector.Valid[0].Document, []byte(vector.DID), []byte("did:key:other"), 1)
	out, code := run(t, []string{"AW_AGENT_STATUS_TEST_SEED_HEX=" + vector.Seed}, wrong, "status", "publish", "--alias", "subject", "--document", "-", "--print-signed", "--json")
	if code != 1 || out["ok"] != false || out["status"] != nil {
		t.Fatalf("publisher mismatch signed: %d %#v", code, out)
	}
	out, code = run(t, []string{"AW_AGENT_STATUS_TEST_SEED_HEX=" + vector.Seed}, vector.Valid[0].Document, "status", "publish", "--alias", "subject", "--document", "-", "--json")
	if code != 1 || out["ok"] != false {
		t.Fatalf("test key accepted online: %d %#v", code, out)
	}
	// Both flag and environment principals sign with their key from an empty instance.
	seed, _ := hex.DecodeString(vector.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	var mu sync.Mutex
	var calls []string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		payload, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		var envelope map[string]any
		_ = json.Unmarshal(payload, &envelope)
		hash := sha256.Sum256(body)
		auth := strings.Fields(r.Header.Get("Authorization"))
		sig := []byte(nil)
		if len(auth) == 3 {
			sig, _ = base64.RawStdEncoding.DecodeString(auth[2])
		}
		if len(auth) != 3 || auth[1] != vector.DID || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, sig) || envelope["v"] != float64(2) || envelope["method"] != r.Method || envelope["path"] != r.URL.RequestURI() || envelope["team_id"] != "default:acme.aweb.ai" || envelope["body_sha256"] != hex.EncodeToString(hash[:]) {
			t.Errorf("bad team-auth v2: %s %s", auth, payload)
		}
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/agents/transport/status":
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		case "/v1/agents/me/status-host":
			if r.Method == "PUT" && !bytes.Contains(body, []byte(vector.DID)) {
				t.Error("wrong host body")
			}
			_, _ = io.WriteString(w, `{"alias":"attached","host_did":null}`)
		case "/v1/agents/subject/status":
			var signed map[string]string
			_ = json.Unmarshal(body, &signed)
			if signed["signed_payload"] != vector.Valid[0].Payload || signed["signature"] != vector.Valid[0].Signature {
				t.Error("online signature differs from vector")
			}
			_, _ = io.WriteString(w, `{"stored":true}`)
		default:
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"detail":"rate_limited: at most one status per agent every 5 seconds"}`)
		}
	}))
	parent := filepath.Join(root, "principal")
	writeSelectionFixtureForTest(t, parent, testSelectionFixture{AwebURL: server.URL, TeamID: "default:acme.aweb.ai", Alias: "attached", DID: vector.DID, StableID: awid.ComputeStableID(key.Public().(ed25519.PublicKey)), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: key})
	for _, byFlag := range []bool{false, true} {
		env := []string{"AWEB_IDENTITY_HOME=" + filepath.Join(parent, ".aw")}
		prefix := []string{}
		if byFlag {
			env = nil
			prefix = []string{"--identity-home", filepath.Join(parent, ".aw")}
		}
		commands := [][]string{{"status-host", "set", "--host-did", vector.DID}, {"status-host", "show"}, {"status-host", "clear"}, {"status", "publish", "--alias", "subject", "--document", "-"}}
		for _, args := range commands {
			out, code := run(t, env, vector.Valid[0].Document, append(prefix, append(args, "--json")...)...)
			if code != 0 || out["ok"] != true || out["status"] != float64(200) {
				t.Fatalf("command %v: %d %#v", args, code, out)
			}
		}
		out, code := run(t, env, vector.Valid[0].Document, append(prefix, "status", "publish", "--alias", "refused", "--document", "-", "--json")...)
		if code != 3 || out["code"] != "rate_limited" || out["message"] != "at most one status per agent every 5 seconds" || out["retry_after"] != float64(5) {
			t.Fatalf("refusal: %d %#v", code, out)
		}
		out, code = run(t, env, vector.Valid[0].Document, append(prefix, "status", "publish", "--alias", "subject", "--document", "-", "--print-signed")...)
		if code != 0 || out["signature"] != vector.Valid[0].Signature {
			t.Fatalf("normal offline signer: %d %#v", code, out)
		}
		out, code = run(t, env, vector.Valid[0].Document, append(prefix, "status", "publish", "--alias", "transport", "--document", "-", "--json")...)
		if code != 1 || out["code"] != "transport" || out["status"] != nil {
			t.Fatalf("transport: %d %#v", code, out)
		}
	}
	for _, args := range [][]string{
		{"status", "publish", "--json"},
		{"--identity-home", "relative", "status-host", "show", "--json"},
		{"status-host", "show", "--unknown", "--json"},
	} {
		out, code := run(t, nil, nil, args...)
		if code != 1 || out["ok"] != false || out["status"] != nil {
			t.Fatalf("local error %v: %d %#v", args, code, out)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 12 {
		t.Fatalf("unexpected network/renewal: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("wrote instance identity: %v", err)
	}
}

func TestAgentStatusCanonicalUnicodeAndExactInteger(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	// Raw U+2028/U+2029 must remain UTF-8, while literal escape text is untouched.
	raw := []byte(`{"seq":9007199254740991,"publisher_did":"` + did + `","reason":{"text":"é<>\u2028\u2029 and literal \\u2028"}}`)
	signed, err := signAgentStatus(raw, &localSigningIdentity{DIDKey: did, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(signed["signed_payload"])
	want := `{"publisher_did":"` + did + `","reason":{"text":"é<>` + "\u2028\u2029" + ` and literal \\u2028"},"seq":9007199254740991}`
	if string(payload) != want {
		t.Fatalf("canonical UTF-8/integer: got %q want %q", payload, want)
	}
}
