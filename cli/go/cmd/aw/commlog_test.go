package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/chat"
)

func TestAppendCommLog(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")

	entry := &CommLogEntry{
		Timestamp: "2026-02-26T10:30:00Z",
		Dir:       "send",
		Channel:   "mail",
		MessageID: "msg-1",
		From:      "demo/rose",
		To:        "demo/eve",
		Subject:   "hello",
		Body:      "test body",
	}

	appendCommLog(logDir, "acct-test", entry)

	logFile := filepath.Join(logDir, "acct-test.jsonl")

	// File must exist with restricted permissions.
	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissions=%o, want 0600", perm)
	}

	// Directory must have restricted permissions.
	dirInfo, err := os.Stat(logDir)
	if err != nil {
		t.Fatalf("log dir not created: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir permissions=%o, want 0700", perm)
	}

	// File must contain exactly one valid JSON line.
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}

	var got CommLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got.Dir != "send" {
		t.Fatalf("dir=%q, want send", got.Dir)
	}
	if got.Channel != "mail" {
		t.Fatalf("channel=%q, want mail", got.Channel)
	}
	if got.MessageID != "msg-1" {
		t.Fatalf("message_id=%q, want msg-1", got.MessageID)
	}
	if got.From != "demo/rose" {
		t.Fatalf("from=%q, want demo/rose", got.From)
	}
	if got.Body != "test body" {
		t.Fatalf("body=%q, want test body", got.Body)
	}
}

func TestAppendCommLogMultipleEntries(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")

	for i := 0; i < 3; i++ {
		appendCommLog(logDir, "acct-multi", &CommLogEntry{
			Timestamp: "2026-02-26T10:30:00Z",
			Dir:       "send",
			Channel:   "chat",
			MessageID: "msg-" + string(rune('a'+i)),
			Body:      "message",
		})
	}

	data, err := os.ReadFile(filepath.Join(logDir, "acct-multi.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}

	// Each line must be valid JSON.
	for i, line := range lines {
		var e CommLogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d: invalid json: %v", i, err)
		}
	}
}

func TestReadCommLog(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")

	entries := []*CommLogEntry{
		{Timestamp: "2026-02-26T10:00:00Z", Dir: "send", Channel: "mail", MessageID: "m1", From: "demo/rose", To: "demo/eve", Subject: "hi", Body: "hello"},
		{Timestamp: "2026-02-26T10:01:00Z", Dir: "recv", Channel: "mail", MessageID: "m2", From: "demo/eve", To: "demo/rose", Subject: "re: hi", Body: "hey"},
		{Timestamp: "2026-02-26T10:02:00Z", Dir: "send", Channel: "chat", MessageID: "m3", From: "demo/rose", To: "demo/eve", Body: "chat msg"},
	}
	for _, e := range entries {
		appendCommLog(logDir, "acct-test", e)
	}

	// Read all.
	got, err := readCommLog(filepath.Join(logDir, "acct-test.jsonl"), 0)
	if err != nil {
		t.Fatalf("readCommLog: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}

	// Read with limit.
	got, err = readCommLog(filepath.Join(logDir, "acct-test.jsonl"), 2)
	if err != nil {
		t.Fatalf("readCommLog limit: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (last 2)", len(got))
	}
	// Should be the last 2 entries.
	if got[0].MessageID != "m2" {
		t.Fatalf("first entry message_id=%q, want m2", got[0].MessageID)
	}
	if got[1].MessageID != "m3" {
		t.Fatalf("second entry message_id=%q, want m3", got[1].MessageID)
	}
}

func TestReadCommLogFilters(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")

	entries := []*CommLogEntry{
		{Timestamp: "2026-02-26T10:00:00Z", Dir: "send", Channel: "mail", From: "demo/rose", To: "demo/eve"},
		{Timestamp: "2026-02-26T10:01:00Z", Dir: "recv", Channel: "chat", From: "demo/eve", To: "demo/rose"},
		{Timestamp: "2026-02-26T10:02:00Z", Dir: "send", Channel: "chat", From: "demo/rose", To: "demo/sam"},
	}
	for _, e := range entries {
		appendCommLog(logDir, "acct-test", e)
	}

	all, _ := readCommLog(filepath.Join(logDir, "acct-test.jsonl"), 0)

	// Filter by channel.
	got := filterCommLog(all, "chat", "")
	if len(got) != 2 {
		t.Fatalf("channel filter: got %d, want 2", len(got))
	}

	// Filter by from.
	got = filterCommLog(all, "", "eve")
	if len(got) != 1 {
		t.Fatalf("from filter: got %d, want 1", len(got))
	}

	// Both filters.
	got = filterCommLog(all, "chat", "rose")
	if len(got) != 1 {
		t.Fatalf("combined filter: got %d, want 1", len(got))
	}
}

func TestFormatLogEntry(t *testing.T) {
	t.Parallel()

	entry := CommLogEntry{
		Timestamp: "2026-02-26T10:30:00Z",
		Dir:       "send",
		Channel:   "mail",
		From:      "demo/rose",
		To:        "demo/eve",
		Subject:   "hello",
		Body:      "test body",
	}
	s := formatLogLine(&entry)
	if !strings.Contains(s, "→") {
		t.Fatalf("send should contain →: %q", s)
	}
	if !strings.Contains(s, "eve") {
		t.Fatalf("should contain recipient: %q", s)
	}

	entry.Dir = "recv"
	entry.From = "demo/eve"
	entry.To = "demo/rose"
	s = formatLogLine(&entry)
	if !strings.Contains(s, "←") {
		t.Fatalf("recv should contain ←: %q", s)
	}
}

func TestLogChatEventTreatsSelfAliasAsSentWhenAddressMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")

	logChatEvent(logDir, "acct-test", "acme.com/wendy", chat.Event{
		Type:      "message",
		MessageID: "msg-self-1",
		FromAgent: "wendy",
		Body:      "self echo",
	})

	entries, err := readCommLog(filepath.Join(logDir, "acct-test.jsonl"), 0)
	if err != nil {
		t.Fatalf("readCommLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	if entries[0].Dir != "send" {
		t.Fatalf("dir=%q, want send", entries[0].Dir)
	}
}

func TestCommLogPathDeterministic(t *testing.T) {
	t.Parallel()

	p1 := commLogPath("/some/dir", "acct-localhost-8000__demo__rose")
	p2 := commLogPath("/some/dir", "acct-localhost-8000__demo__rose")
	if p1 != p2 {
		t.Fatalf("paths differ: %q vs %q", p1, p2)
	}
	if !strings.HasSuffix(p1, ".jsonl") {
		t.Fatalf("path should end in .jsonl: %q", p1)
	}
	if !strings.Contains(p1, "acct-localhost-8000__demo__rose") {
		t.Fatalf("path should contain account name: %q", p1)
	}
}
