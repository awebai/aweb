package main

import (
	"context"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"net/http"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAwMailInboxCountOnlyNeverAcknowledges(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		name     string
		count    int
		failPage bool
		identity string
	}{
		{name: "empty"}, {name: "one-message", count: 1}, {name: "multiple-pages", count: 3},
		{name: "external-local", count: 3, identity: "local"},
		{name: "external-global", count: 3, identity: "global"},
		{name: "read-only-grant", count: 3, identity: "grant"}, {name: "failed-continuation", count: 3, failPage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var acks, fetches atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
					fetches.Add(1)
					if r.URL.Query().Get("unread_only") != "true" {
						t.Errorf("not an unread query: %s", r.URL.RawQuery)
					}
					cursor := r.URL.Query().Get("cursor")
					if tc.failPage && cursor != "" {
						http.Error(w, "unavailable", http.StatusServiceUnavailable)
						return
					}
					messages := []any{}
					more := false
					next := ""
					if tc.count > 0 {
						// Deliberately include encrypted/unverifiable content. Counting must not
						// decrypt, verify senders, or configure/publish encryption keys.
						messages = append(messages, map[string]any{"message_id": "m3", "content_mode": "encrypted_v2", "encrypted_envelope": map[string]any{}})
						if cursor == "" && tc.count > 1 {
							messages = append(messages, map[string]any{"message_id": "m2"})
							more = true
							next = "page-2"
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages, "has_more": more, "next_cursor": next})
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ack"):
					acks.Add(1)
					http.Error(w, "must not acknowledge", http.StatusInternalServerError)
				case r.URL.Path == "/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			}))
			home := t.TempDir()
			writeDefaultWorkspaceBindingForTest(t, home, server.URL)
			args := []string{"mail", "inbox", "--count-only", "--json"}
			identityHome := filepath.Join(home, ".aw")
			if tc.identity != "" {
				selected, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if tc.identity == "grant" {
					identityHome = selected
					_, grant := writeGrantHomeForTest(t, selected, server.URL)
					grant.Scopes = []string{"mail.read"}
					if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(selected), grant); err != nil {
						t.Fatal(err)
					}
				} else {
					pub, key, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					stableID := ""
					if tc.identity == "global" {
						stableID = awid.ComputeStableID(pub)
					}
					writeSelectionFixtureForTest(t, selected, testSelectionFixture{AwebURL: server.URL, TeamID: "backend:demo", Alias: "alice", IdentityScope: tc.identity, SigningKey: key, DID: awid.ComputeDIDKey(pub), StableID: stableID, Custody: awid.CustodySelf, Address: "demo/alice"})
					identityHome = filepath.Join(selected, ".aw")
				}
				args = append([]string{"--identity-home", identityHome}, args...)
			}
			before := fileDigestsForTest(t, identityHome)
			for attempt := 0; attempt < 2; attempt++ {
				commandArgs := args
				if attempt == 1 {
					commandArgs = args[:len(args)-1] // Repeat as human-readable text.
				}
				cmd := exec.CommandContext(ctx, bin, commandArgs...)
				cmd.Env = testCommandEnv(home)
				cmd.Dir = home
				out, err := cmd.CombinedOutput()
				if tc.failPage {
					if err == nil || strings.Contains(string(out), "\"unread_count\"") {
						t.Fatalf("partial count reported success: err=%v out=%s", err, out)
					}
					continue
				}
				if err != nil {
					t.Fatalf("count failed: %v\n%s", err, out)
				}
				if attempt == 1 {
					want := map[int]string{0: "0 unread messages\n", 1: "1 unread message\n", 3: "3 unread messages\n"}[tc.count]
					if string(out) != want {
						t.Fatalf("text count = %q, want %q", out, want)
					}
					continue
				}
				var result map[string]int
				if err := json.Unmarshal(out, &result); err != nil {
					t.Fatal(err)
				}
				if count, ok := result["unread_count"]; !ok || count != tc.count {
					t.Fatalf("count=%v want %d; %s", result, tc.count, out)
				}
			}
			after := fileDigestsForTest(t, identityHome)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("count mutated identity home: before=%v after=%v", before, after)
			}
			if acks.Load() != 0 {
				t.Fatalf("count acknowledged %d messages", acks.Load())
			}
			if !tc.failPage && fetches.Load() == 0 {
				t.Fatal("count did not query server")
			}
		})
	}
	t.Run("flag-errors-before-identity-selection", func(t *testing.T) {
		home := t.TempDir()
		for _, tc := range []struct {
			flag, value, message string
		}{
			{"limit", "1", "--count-only counts every page, so it cannot be combined with --limit."},
			{"cursor", "page-2", "--count-only counts every page, so it cannot be combined with --cursor."},
			{"show-all", "true", "--count-only counts unread messages, so it cannot be combined with --show-all."},
		} {
			for _, jsonOutput := range []bool{false, true} {
				args := []string{"mail", "inbox", "--count-only", "--" + tc.flag + "=" + tc.value}
				if jsonOutput {
					args = append(args, "--json")
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Env = testCommandEnv(home)
				cmd.Dir = home
				out, err := cmd.Output()
				if err == nil {
					t.Fatalf("--%s accepted with count-only", tc.flag)
				}
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 {
					t.Fatalf("--%s exit = %v, want 1", tc.flag, err)
				}
				if jsonOutput {
					var result struct {
						Error struct{ Code, Message string } `json:"error"`
					}
					if err := json.Unmarshal(out, &result); err != nil || result.Error.Code != "error" || result.Error.Message != tc.message {
						t.Fatalf("--%s JSON error = %s, decode=%v", tc.flag, out, err)
					}
				} else {
					if !strings.Contains(string(exit.Stderr), tc.message) {
						t.Fatalf("--%s text error = %v, stderr=%q", tc.flag, err, exit.Stderr)
					}
				}
			}
		}
	})
}
