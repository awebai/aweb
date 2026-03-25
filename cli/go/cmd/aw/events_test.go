package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAwEventsStream(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("response writer does not support flushing")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			fmt.Fprintf(w, "event: connected\ndata: {\"agent_id\":\"a-1\",\"project_id\":\"p-1\"}\n\n")
			flusher.Flush()

			fmt.Fprintf(w, "event: actionable_mail\ndata: {\"message_id\":\"m-1\",\"from_alias\":\"alice\",\"subject\":\"hello\",\"wake_mode\":\"prompt\",\"unread_count\":2}\n\n")
			flusher.Flush()

			// Close to terminate the stream.
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", "5")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()

	output := string(out)
	lines := strings.Split(strings.TrimSpace(output), "\n")

	var events []map[string]any
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev map[string]any
		if jerr := json.Unmarshal([]byte(line), &ev); jerr == nil {
			events = append(events, ev)
		}
	}

	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d (err=%v)\noutput:\n%s", len(events), runErr, output)
	}

	if events[0]["type"] != "connected" {
		t.Fatalf("first event type=%v, want connected", events[0]["type"])
	}
	if events[0]["agent_id"] != "a-1" {
		t.Fatalf("connected agent_id=%v", events[0]["agent_id"])
	}

	if events[1]["type"] != "actionable_mail" {
		t.Fatalf("second event type=%v, want actionable_mail", events[1]["type"])
	}
	if events[1]["message_id"] != "m-1" {
		t.Fatalf("mail message_id=%v", events[1]["message_id"])
	}
	if events[1]["from_alias"] != "alice" {
		t.Fatalf("mail from_alias=%v", events[1]["from_alias"])
	}
	if events[1]["wake_mode"] != "prompt" {
		t.Fatalf("mail wake_mode=%v", events[1]["wake_mode"])
	}
}

func TestAwEventsStreamTextOutput(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("response writer does not support flushing")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			fmt.Fprintf(w, "event: connected\ndata: {\"agent_id\":\"a-1\",\"project_id\":\"p-1\"}\n\n")
			flusher.Flush()

			fmt.Fprintf(w, "event: actionable_mail\ndata: {\"message_id\":\"m-1\",\"from_alias\":\"alice\",\"subject\":\"hello\",\"wake_mode\":\"prompt\",\"unread_count\":2}\n\n")
			flusher.Flush()
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "events", "stream", "--timeout", "5")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()

	output := string(out)
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d (err=%v)\noutput:\n%s", len(lines), runErr, output)
	}

	wantConnected := `[connected] agent_id=a-1 project_id=p-1`
	if strings.TrimSpace(lines[0]) != wantConnected {
		t.Fatalf("line[0]=%q, want %q", lines[0], wantConnected)
	}

	wantMail := `[actionable_mail] from=alice wake_mode=prompt unread=2 message_id=m-1 subject="hello"`
	if strings.TrimSpace(lines[1]) != wantMail {
		t.Fatalf("line[1]=%q, want %q", lines[1], wantMail)
	}
}
