package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestResolveMailTargetKeepsTildeTargetAsAlias(t *testing.T) {
	oldTo, oldToDID, oldToAddress := mailSendTo, mailSendToDID, mailSendToAddress
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
	})

	mailSendTo = "ops~alice"
	mailSendToDID = ""
	mailSendToAddress = ""

	kind, value, err := resolveMailTarget()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "alias" {
		t.Fatalf("kind=%q, want alias", kind)
	}
	if value != "ops~alice" {
		t.Fatalf("value=%q, want ops~alice", value)
	}
}

func TestResolveMailBodyUsesBodyArg(t *testing.T) {
	body, err := resolveMailBody("hello", "")
	if err != nil {
		t.Fatal(err)
	}
	if body != "hello" {
		t.Fatalf("body=%q, want hello", body)
	}
}

func TestResolveMailBodyMutualExclusion(t *testing.T) {
	_, err := resolveMailBody("hello", "/some/path")
	if err == nil {
		t.Fatal("expected error when both --body and --body-file set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err=%q, want mutually exclusive", err)
	}
}

func TestResolveMailBodyMissingFlags(t *testing.T) {
	_, err := resolveMailBody("", "")
	if err == nil {
		t.Fatal("expected error when neither flag set")
	}
	if !strings.Contains(err.Error(), "missing required flag") {
		t.Fatalf("err=%q, want missing required flag", err)
	}
	if !strings.Contains(err.Error(), "--body") || !strings.Contains(err.Error(), "--body-file") {
		t.Fatalf("err=%q, want both --body and --body-file mentioned", err)
	}
}

func TestResolveMailBodyReadsFileVerbatimWithBackticks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body.md")
	content := "look at `config.ts` line 42 and ${VAR} stays as ${VAR}"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	body, err := resolveMailBody("", path)
	if err != nil {
		t.Fatal(err)
	}
	if body != content {
		t.Fatalf("body=%q, want %q", body, content)
	}
}

func TestResolveMailBodyStripsExactlyOneTrailingNewline(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"no newline", "X", "X"},
		{"single newline", "X\n", "X"},
		{"double newline becomes single", "X\n\n", "X\n"},
		{"internal newline preserved", "line1\nline2\n", "line1\nline2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			body, err := resolveMailBody("", path)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if body != tc.want {
				t.Fatalf("body=%q, want %q", body, tc.want)
			}
		})
	}
}

func TestResolveMailBodyEmptyFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveMailBody("", path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%q, want empty mentioned", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("err=%q, want path %q mentioned", err, path)
	}
}

func TestResolveMailBodyNewlineOnlyFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newline_only")
	if err := os.WriteFile(path, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveMailBody("", path)
	if err == nil {
		t.Fatal("expected error: file with only a trailing newline strips to empty")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%q, want empty mentioned", err)
	}
}

func TestResolveMailBodyMissingFileErrors(t *testing.T) {
	_, err := resolveMailBody("", filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "body file") {
		t.Fatalf("err=%q, want body file mentioned", err)
	}
}

func TestAwMailSendBodyFilePreservesBackticksOnTheWire(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)

	bodyContent := "look at `config.ts` line 42 and ${VAR} stays literal\nsecond `paragraph` here"

	type captured struct {
		Body string `json:"body"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-aalh-1",
				"status":       "delivered",
				"delivered_at": "2026-04-26T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-26T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	bodyFile := filepath.Join(tmp, "body.md")
	if err := os.WriteFile(bodyFile, []byte(bodyContent), 0o644); err != nil {
		t.Fatalf("write body file: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-did", "did:aw:monitor",
		"--body-file", bodyFile,
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if got.Body != bodyContent {
		t.Fatalf("body on wire=%q, want %q", got.Body, bodyContent)
	}
}

func TestAwMailSendRejectsBothBodyAndBodyFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "http://127.0.0.1:1")

	bodyFile := filepath.Join(tmp, "body.md")
	if err := os.WriteFile(bodyFile, []byte("from file"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "alice",
		"--body", "from flag",
		"--body-file", bodyFile,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got:\n%s", string(out))
	}
}
