package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/chat"
)

func TestNotifyCooldownSkipsRecentCheck(t *testing.T) {
	t.Parallel()

	stampPath := filepath.Join(t.TempDir(), "stamp")
	// No stamp file → should not skip.
	if notifyCooldownActive(stampPath, 10*time.Second) {
		t.Fatal("should not skip when stamp file does not exist")
	}
	// Touch the stamp file.
	touchNotifyStamp(stampPath)
	// Stamp just created → should skip.
	if !notifyCooldownActive(stampPath, 10*time.Second) {
		t.Fatal("should skip when stamp was just touched")
	}
}

func TestNotifyCooldownExpiresAfterDuration(t *testing.T) {
	t.Parallel()

	stampPath := filepath.Join(t.TempDir(), "stamp")
	touchNotifyStamp(stampPath)
	// With a zero cooldown → should not skip.
	if notifyCooldownActive(stampPath, 0) {
		t.Fatal("should not skip with zero cooldown")
	}
}

func TestNotifyStampPathIsScopedByConfigPath(t *testing.T) {
	t.Parallel()

	first := notifyStampPath("notify-pending", "/tmp/config-a.yaml")
	second := notifyStampPath("notify-pending", "/tmp/config-b.yaml")
	if first == second {
		t.Fatalf("stamp path should differ across config scopes: %q", first)
	}
}

func TestFormatNotifyOutputNoPending(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{Pending: nil}
	if got := formatNotifyOutput(result, "wendy"); got != "" {
		t.Fatalf("expected empty output, got %q", got)
	}
}

func TestFormatNotifyOutputUrgentAndFallback(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				SessionID:     "s1",
				Participants:  []string{"wendy", "rose"},
				LastFrom:      "rose",
				UnreadCount:   1,
				SenderWaiting: true,
			},
			{
				SessionID:     "s2",
				Participants:  []string{"wendy", "henry"},
				LastFrom:      "",
				UnreadCount:   1,
				SenderWaiting: false,
			},
		},
	}

	out := formatNotifyOutput(result, "wendy", "did:aw:wendy", "did:key:self-wendy")
	for _, want := range []string{
		"URGENT",
		"rose",
		"Unread message from henry",
		"YOU MUST RUN: aw chat pending",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatNotifyOutputFallbackSkipsSelfAddress(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				SessionID:            "s1",
				Participants:         []string{"wendy", "rose"},
				ParticipantAddresses: []string{"acme.com/wendy", "otherco/rose"},
				LastFrom:             "",
				UnreadCount:          1,
				SenderWaiting:        false,
			},
		},
	}

	out := formatNotifyOutput(result, "wendy", "did:aw:wendy", "did:key:self-wendy")
	if !strings.Contains(out, "Unread message from otherco/rose") {
		t.Fatalf("notify output should fall back to the non-self participant address:\n%s", out)
	}
	if strings.Contains(out, "Unread message from acme.com/wendy") {
		t.Fatalf("notify output should not surface self address as sender:\n%s", out)
	}
}

func TestFormatNotifyOutputSkipsDirectSelfAddressSender(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				SessionID:            "s1",
				Participants:         []string{"wendy", "rose"},
				ParticipantAddresses: []string{"acme.com/wendy", "otherco/rose"},
				LastFrom:             "wendy",
				LastFromAddress:      "acme.com/wendy",
				LastMessage:          "note to self",
				UnreadCount:          1,
				SenderWaiting:        false,
			},
		},
	}

	out := formatNotifyOutput(result, "wendy")
	if out != "" {
		t.Fatalf("notify output should skip direct self-authored sender labels:\n%s", out)
	}
}

func TestFormatNotifyOutputFallsBackToStableID(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				SessionID:            "s1",
				Participants:         []string{"", ""},
				ParticipantDIDs:      []string{"did:aw:wendy", "did:aw:rose"},
				ParticipantAddresses: []string{"", ""},
				LastFrom:             "",
				LastFromDID:          "did:aw:rose",
				LastFromAddress:      "",
				UnreadCount:          1,
				SenderWaiting:        false,
			},
		},
	}

	out := formatNotifyOutput(result, "wendy")
	if !strings.Contains(out, "Unread message from did:aw:rose") {
		t.Fatalf("notify output should preserve stable identity fallback:\n%s", out)
	}
}

func TestFormatNotifyOutputSkipsSelfStableIDParticipant(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				SessionID:            "s1",
				Participants:         []string{"", ""},
				ParticipantDIDs:      []string{"did:aw:wendy", "did:aw:rose"},
				ParticipantAddresses: []string{"", ""},
				LastFrom:             "",
				LastFromAddress:      "",
				UnreadCount:          1,
				SenderWaiting:        false,
			},
		},
	}

	out := formatNotifyOutput(result, "wendy")
	if strings.Contains(out, "Unread message from did:aw:wendy") {
		t.Fatalf("notify output should not surface self stable identity as sender:\n%s", out)
	}
	if !strings.Contains(out, "Unread message from did:aw:rose") {
		t.Fatalf("notify output should skip self stable identity and fall through to the other participant:\n%s", out)
	}
}

func TestFormatNotifyOutputSkipsSelfCurrentDIDParticipant(t *testing.T) {
	t.Parallel()

	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				SessionID:            "s1",
				Participants:         []string{"", ""},
				ParticipantDIDs:      []string{"did:key:self-wendy", "did:aw:rose"},
				ParticipantAddresses: []string{"", ""},
				LastFrom:             "",
				LastFromAddress:      "",
				UnreadCount:          1,
				SenderWaiting:        false,
			},
		},
	}

	out := formatNotifyOutput(result, "wendy", "did:aw:wendy", "did:key:self-wendy")
	if strings.Contains(out, "Unread message from did:key:self-wendy") {
		t.Fatalf("notify output should not surface self current did as sender:\n%s", out)
	}
	if !strings.Contains(out, "Unread message from did:aw:rose") {
		t.Fatalf("notify output should skip self current did and fall through to the other participant:\n%s", out)
	}
}

func TestFormatHookOutputValidJSON(t *testing.T) {
	t.Parallel()

	content := "notify content"
	out := formatHookOutput(content)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	hook, ok := parsed["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput: %#v", parsed)
	}
	if hook["hookEventName"] != "PostToolUse" {
		t.Fatalf("hookEventName=%v", hook["hookEventName"])
	}
	if hook["additionalContext"] != content {
		t.Fatalf("additionalContext=%v", hook["additionalContext"])
	}
}

func TestAwNotifySilentWithoutConfig(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "notify")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("notify should exit cleanly, got %v\n%s", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("expected no output, got:\n%s", string(out))
	}
}

func TestAwNotifySilentOnAPIError(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/pending":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"detail":"boom"}`))
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "notify-api-error", "workspace-1"))

	run := exec.CommandContext(ctx, bin, "notify")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("notify should exit cleanly, got %v\n%s", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("expected no output, got:\n%s", string(out))
	}
}

func TestAwNotifyOutputsHookJSONWhenPendingChatsExist(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pending": []map[string]any{
					{
						"session_id":             "s1",
						"participants":           []string{"wendy", "rose"},
						"participant_addresses":  []string{"acme.com/wendy", "otherco/rose"},
						"last_message":           "reply?",
						"last_from":              "rose",
						"last_from_address":      "otherco/rose",
						"unread_count":           1,
						"last_activity":          "2026-03-21T12:00:00Z",
						"sender_waiting":         true,
						"time_remaining_seconds": 30,
					},
				},
				"messages_waiting": 1,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "notify-pending", "workspace-1"))

	run := exec.CommandContext(ctx, bin, "notify")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("notify failed: %v\n%s", err, string(out))
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	hook := parsed["hookSpecificOutput"].(map[string]any)
	contextText := hook["additionalContext"].(string)
	for _, want := range []string{"URGENT", "otherco/rose", "aw chat pending"} {
		if !strings.Contains(contextText, want) {
			t.Fatalf("missing %q in context:\n%s", want, contextText)
		}
	}
}
