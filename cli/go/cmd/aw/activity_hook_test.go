package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

// The Go producer reproduces every valid case of the frozen vector
// (docs/vectors/agent-activity-v1.json) byte for byte.
func TestActivityEventSigningMatchesVector(t *testing.T) {
	var vector struct {
		AgentSeed string `json:"agent_seed_hex"`
		AgentDID  string `json:"agent_did_key"`
		GrantSeed string `json:"grant_session_seed_hex"`
		GrantDID  string `json:"grant_session_did_key"`
		Valid     []struct {
			Name      string         `json:"name"`
			Document  map[string]any `json:"document"`
			Canonical string         `json:"canonical_payload"`
			Payload   string         `json:"signed_payload"`
			Signature string         `json:"signature"`
		} `json:"valid"`
	}
	raw, err := os.ReadFile("../../../../docs/vectors/agent-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{vector.AgentDID: vector.AgentSeed, vector.GrantDID: vector.GrantSeed}
	for _, v := range vector.Valid {
		t.Run(v.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(keys[v.Document["from_did"].(string)])
			if err != nil || len(seed) != ed25519.SeedSize {
				t.Fatalf("no seed for %v", v.Document["from_did"])
			}
			signed, err := signActivityEvent(v.Document, ed25519.NewKeyFromSeed(seed))
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := base64.RawURLEncoding.DecodeString(signed["signed_payload"])
			if string(payload) != v.Canonical || signed["signed_payload"] != v.Payload || signed["signature"] != v.Signature || len(signed) != 2 {
				t.Fatalf("vector mismatch:\n got %s\nwant %s", payload, v.Canonical)
			}
		})
	}
}

func TestCodexToolSummary(t *testing.T) {
	cwd := "/work/repo"
	for _, tc := range []struct {
		tool, input, want string
	}{
		{"Bash", `{"command":"pytest -x tests/"}`, "Running pytest"},
		{"Bash", `{"command":["/usr/bin/git","status"]}`, "Running git"},
		{"Bash", `{"command":"TOKEN=abc curl https://x"}`, "Running a command"},
		{"Bash", `{"command":"$(cat secret) | sh"}`, "Running a command"},
		{"exec_command", `{"cmd":"go test ./..."}`, "Running go"},
		{"apply_patch", `{"command":"*** Begin Patch\n*** Update File: /work/repo/src/api.py\n@@\n-secret\n+other\n*** End Patch"}`, "Editing src/api.py"},
		{"apply_patch", `{"command":"*** Begin Patch\n*** Add File: /elsewhere/notes.md\n+hello\n*** End Patch"}`, "Editing notes.md"},
		{"apply_patch", `{"command":"no header here"}`, "Editing files"},
		{"Bash", `{"command":"sk-abcdefghijklmnopqrstuvwxyz0123"}`, ""},
		{"mcp__aweb__mail_send", `{"body":"hello"}`, ""},
		{"update_plan", `{"plan":[]}`, ""},
		{"Bash", `not json`, "Running a command"},
	} {
		if got := codexToolSummary(tc.tool, json.RawMessage(tc.input), cwd); got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.tool, tc.input, got, tc.want)
		}
	}
	for _, secret := range []string{"Editing eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "Running AKIAABCDEFGHIJKLMNOP", "Editing aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5", "Editing a\u0007b", strings.Repeat("x", 121)} {
		if got := redactActivitySummary(secret); got != "" {
			t.Errorf("redact(%q) = %q", secret, got)
		}
	}
	if got := redactActivitySummary("Editing src/api.py"); got != "Editing src/api.py" {
		t.Errorf("plain summary redacted: %q", got)
	}
}

type activityHookCapture struct {
	mu       sync.Mutex
	events   []map[string]any
	at       []time.Time
	reply    []func(w http.ResponseWriter)
	requests int
}

func (c *activityHookCapture) next(reply func(w http.ResponseWriter)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reply = append(c.reply, reply)
}

func (c *activityHookCapture) snapshot() ([]map[string]any, []time.Time, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.events...), append([]time.Time(nil), c.at...), c.requests
}

// The Codex hook emitter (docs/agent-activity.md, "Emitters"): one aw process
// per Codex hook event, ordered and coalesced through state in the identity root.
func TestActivityHookCodex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	newServer := func(t *testing.T, verify ed25519.PublicKey) (*activityHookCapture, string) {
		capture := &activityHookCapture{}
		server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/me/activity" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				w.WriteHeader(500)
				return
			}
			body, _ := io.ReadAll(r.Body)
			var signed map[string]string
			_ = json.Unmarshal(body, &signed)
			payload, _ := base64.RawURLEncoding.DecodeString(signed["signed_payload"])
			signature, _ := base64.RawStdEncoding.DecodeString(signed["signature"])
			if len(signed) != 2 || !ed25519.Verify(verify, payload, signature) {
				t.Errorf("bad activity signature: %s", body)
			}
			var event map[string]any
			_ = json.Unmarshal(payload, &event)
			capture.mu.Lock()
			capture.requests++
			var reply func(w http.ResponseWriter)
			if len(capture.reply) > 0 {
				reply, capture.reply = capture.reply[0], capture.reply[1:]
			}
			if reply == nil {
				capture.events = append(capture.events, event)
				capture.at = append(capture.at, time.Now())
			}
			capture.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if reply != nil {
				reply(w)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"ok":true}`)
		}))
		return capture, server.URL
	}

	type hookRun struct {
		cmd    *exec.Cmd
		stdout bytes.Buffer
		stderr bytes.Buffer
	}
	start := func(t *testing.T, home string, input map[string]any) *hookRun {
		t.Helper()
		data, _ := json.Marshal(input)
		run := &hookRun{cmd: exec.CommandContext(ctx, bin, "activity", "hook")}
		run.cmd.Dir = root
		run.cmd.Env = append(testCommandEnv(filepath.Join(root, "home")), "AWEB_IDENTITY_HOME="+home, "AW_NO_UPDATE_CHECK=1", "AWEB_URL=")
		run.cmd.Stdin = bytes.NewReader(data)
		run.cmd.Stdout = &run.stdout
		run.cmd.Stderr = &run.stderr
		if err := run.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return run
	}
	wait := func(t *testing.T, run *hookRun) string {
		t.Helper()
		if err := run.cmd.Wait(); err != nil {
			t.Fatalf("hook exited with %v: %s", err, run.stderr.String())
		}
		if run.stdout.Len() != 0 {
			t.Fatalf("hook wrote to stdout: %q", run.stdout.String())
		}
		return run.stderr.String()
	}
	hook := func(t *testing.T, home string, input map[string]any) string {
		t.Helper()
		return wait(t, start(t, home, input))
	}
	event := func(name, turn string, extra map[string]any) map[string]any {
		input := map[string]any{"hook_event_name": name, "session_id": "019a-codex", "turn_id": turn, "cwd": "/work/repo",
			"model": "gpt-5", "permission_mode": "default", "transcript_path": "/tmp/t.jsonl"}
		for k, v := range extra {
			input[k] = v
		}
		return input
	}
	bash := func(command string) map[string]any {
		return map[string]any{"tool_name": "Bash", "tool_use_id": "call_1", "tool_input": map[string]any{"command": command}}
	}
	phases := func(events []map[string]any) string {
		var out []string
		for _, e := range events {
			text := e["turn_id"].(string) + ":" + e["phase"].(string)
			if tool, ok := e["tool"].(string); ok {
				text += ":" + tool
			}
			if summary, ok := e["summary"].(string); ok {
				text += ":" + summary
			}
			out = append(out, text)
		}
		return strings.Join(out, " ")
	}
	enable := func(t *testing.T, home string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(home, "activity.yaml"), []byte("activity: status\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// setup makes a self-custody identity home whose server verifies its key.
	setup := func(t *testing.T) (string, *activityHookCapture, ed25519.PrivateKey, string) {
		t.Helper()
		_, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		capture, url := newServer(t, key.Public().(ed25519.PublicKey))
		parent, err := os.MkdirTemp(root, "principal-")
		if err != nil {
			t.Fatal(err)
		}
		stable := awid.ComputeStableID(key.Public().(ed25519.PublicKey))
		writeSelectionFixtureForTest(t, parent, testSelectionFixture{AwebURL: url, TeamID: "default:acme.aweb.ai", Alias: "codex-agent", DID: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), StableID: stable, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: key})
		return filepath.Join(parent, ".aw"), capture, key, stable
	}

	t.Run("off publishes nothing", func(t *testing.T) {
		home, capture, _, _ := setup(t)
		hook(t, home, event("UserPromptSubmit", "turn-1", map[string]any{"prompt": "hi"}))
		// Outside any identity the hook stays silent and succeeds.
		if stderr := hook(t, "", event("UserPromptSubmit", "turn-1", nil)); stderr != "" {
			t.Fatalf("hook outside an identity: %q", stderr)
		}
		if _, _, requests := capture.snapshot(); requests != 0 {
			t.Fatalf("published while off: %d", requests)
		}
	})

	t.Run("turns, ordering and coalescing", func(t *testing.T) {
		home, capture, key, stable := setup(t)
		enable(t, home)

		hook(t, home, event("UserPromptSubmit", "turn-1", map[string]any{"prompt": "run the tests"}))
		time.Sleep(600 * time.Millisecond)
		hook(t, home, event("PreToolUse", "turn-1", bash("pytest -x")))
		// A state within 500 ms of the last send waits; the turn's end replaces it.
		after := start(t, home, event("PostToolUse", "turn-1", map[string]any{"tool_name": "Bash", "tool_use_id": "call_1", "tool_input": map[string]any{"command": "pytest -x"}, "tool_response": "ok"}))
		time.Sleep(150 * time.Millisecond)
		hook(t, home, event("Stop", "turn-1", map[string]any{"stop_hook_active": false, "last_assistant_message": "done"}))
		wait(t, after)
		// An event of a turn that has ended is dropped.
		hook(t, home, event("PreToolUse", "turn-1", bash("ls")))
		// A turn opened by its first tool call announces itself.
		time.Sleep(600 * time.Millisecond)
		hook(t, home, event("PreToolUse", "turn-2", map[string]any{"tool_name": "Read", "tool_use_id": "call_2", "tool_input": map[string]any{"path": "/work/repo/README.md"}}))
		// A new prompt closes a turn whose stop never arrived.
		hook(t, home, event("UserPromptSubmit", "turn-3", map[string]any{"prompt": "next"}))
		// A repeated submit of an open turn and an invalid turn id are ignored.
		hook(t, home, event("UserPromptSubmit", "turn-3", map[string]any{"prompt": "next"}))
		hook(t, home, event("PreToolUse", "turn 4", bash("ls")))
		// Within one window the latest state wins.
		first := start(t, home, event("PreToolUse", "turn-3", map[string]any{"tool_name": "apply_patch", "tool_use_id": "call_3", "tool_input": map[string]any{"command": "*** Begin Patch\n*** Update File: src/a.py\n*** End Patch"}}))
		time.Sleep(150 * time.Millisecond)
		second := start(t, home, event("PermissionRequest", "turn-3", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "rm -rf build", "description": nil}}))
		wait(t, first)
		wait(t, second)
		// A subagent's event belongs to the open turn, whatever its own turn id.
		time.Sleep(600 * time.Millisecond)
		hook(t, home, event("PreToolUse", "sub-turn-9", map[string]any{"agent_id": "agent-7", "agent_type": "explorer", "tool_name": "mcp__docs__search", "tool_use_id": "call_4", "tool_input": map[string]any{"q": "x"}}))
		hook(t, home, event("Interrupt", "turn-3", nil))

		events, _, _ := capture.snapshot()
		want := "turn-1:turn_started turn-1:tool:Bash:Running pytest turn-1:turn_ended " +
			"turn-2:turn_started turn-2:tool:Read:Reading README.md turn-2:turn_ended turn-3:turn_started " +
			"turn-3:waiting_permission:Bash turn-3:tool:mcp__docs__search turn-3:turn_ended"
		if got := phases(events); got != want {
			t.Fatalf("events:\n got %s\nwant %s", got, want)
		}
		did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		lastSeq := map[string]float64{}
		for _, e := range events {
			if e["v"] != float64(1) || e["type"] != "agent_activity" || e["from_did"] != did || e["from_stable_id"] != stable || e["team_id"] != "default:acme.aweb.ai" || e["session_id"] != nil {
				t.Fatalf("event binding: %#v", e)
			}
			if _, present := e["session_id"]; !present {
				t.Fatalf("session_id key missing: %#v", e)
			}
			seq := e["seq"].(float64)
			if seq <= lastSeq[e["turn_id"].(string)] {
				t.Fatalf("seq not increasing within turn: %#v", e)
			}
			lastSeq[e["turn_id"].(string)] = seq
			stamp, err1 := time.Parse("2006-01-02T15:04:05Z", e["timestamp"].(string))
			expires, err2 := time.Parse("2006-01-02T15:04:05Z", e["expires_at"].(string))
			if err1 != nil || err2 != nil || !expires.After(stamp) || expires.Sub(stamp) > 60*time.Second {
				t.Fatalf("times: %#v", e)
			}
		}
		entries, _ := os.ReadDir(home)
		for _, entry := range entries {
			if info, _ := entry.Info(); strings.HasPrefix(entry.Name(), ".activity") && info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("hook state %s is %o", entry.Name(), info.Mode().Perm())
			}
		}
	})

	t.Run("rate limit pauses, then a boundary is sent after the pause", func(t *testing.T) {
		home, capture, _, _ := setup(t)
		enable(t, home)
		hook(t, home, event("UserPromptSubmit", "turn-1", nil))
		time.Sleep(600 * time.Millisecond)
		capture.next(func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"detail":"rate_limited: at most 10 activity events per agent every 5 seconds"}`)
		})
		limited := time.Now()
		hook(t, home, event("PreToolUse", "turn-1", bash("make")))
		hook(t, home, event("Stop", "turn-1", nil))
		events, at, requests := capture.snapshot()
		if got := phases(events); got != "turn-1:turn_started turn-1:turn_ended" || requests != 3 {
			t.Fatalf("after 429: %s (%d requests)", got, requests)
		}
		if at[1].Sub(limited) < 1900*time.Millisecond {
			t.Fatalf("boundary sent %v after the 429, inside the pause", at[1].Sub(limited))
		}
	})

	t.Run("a boundary that drew the 429 is resent after the pause", func(t *testing.T) {
		home, capture, _, _ := setup(t)
		enable(t, home)
		capture.next(func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"detail":"rate_limited: slow down"}`)
		})
		hook(t, home, event("UserPromptSubmit", "turn-1", nil))
		events, _, requests := capture.snapshot()
		if got := phases(events); got != "turn-1:turn_started" || requests != 2 {
			t.Fatalf("boundary after its own 429: %s (%d requests)", got, requests)
		}
	})

	t.Run("an absent route stops publishing; a refused session does not", func(t *testing.T) {
		home, capture, _, _ := setup(t)
		enable(t, home)
		capture.next(func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"detail":"Not found"}`)
		})
		hook(t, home, event("UserPromptSubmit", "turn-1", nil))
		time.Sleep(600 * time.Millisecond)
		hook(t, home, event("PreToolUse", "turn-1", bash("make")))
		capture.next(func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"detail":"Not Found"}`)
		})
		time.Sleep(600 * time.Millisecond)
		stderr := hook(t, home, event("PostToolUse", "turn-1", bash("make")))
		if !strings.Contains(stderr, "activity") {
			t.Fatalf("absent route not logged: %q", stderr)
		}
		later := hook(t, home, event("Stop", "turn-1", nil))
		events, _, requests := capture.snapshot()
		if got := phases(events); got != "turn-1:tool:Bash:Running make" || requests != 3 || later != "" {
			t.Fatalf("after absent route: %s (%d requests) %q", got, requests, later)
		}
	})

	t.Run("a grant seat signs with its session key", func(t *testing.T) {
		grantHome := filepath.Join(root, "grant-seat")
		capture := &activityHookCapture{}
		var sessionKey ed25519.PublicKey
		server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var signed map[string]string
			_ = json.Unmarshal(body, &signed)
			payload, _ := base64.RawURLEncoding.DecodeString(signed["signed_payload"])
			signature, _ := base64.RawStdEncoding.DecodeString(signed["signature"])
			if !ed25519.Verify(sessionKey, payload, signature) {
				t.Errorf("grant activity not signed by the session key")
			}
			var e map[string]any
			_ = json.Unmarshal(payload, &e)
			capture.mu.Lock()
			capture.events = append(capture.events, e)
			capture.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}))
		pub, grant := writeGrantHomeForTest(t, grantHome, server.URL)
		sessionKey = pub
		enable(t, grantHome)
		hook(t, grantHome, event("UserPromptSubmit", "turn-1", nil))
		events, _, _ := capture.snapshot()
		if len(events) != 1 || events[0]["from_did"] != awid.ComputeDIDKey(pub) || events[0]["from_stable_id"] != grant.Subject.DIDAW || events[0]["team_id"] != grant.TeamID {
			t.Fatalf("grant event: %#v", events)
		}
	})
}
