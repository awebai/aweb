package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendInteractionLogForDirDedupesByMessageID(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}

	entry := &InteractionEntry{
		Timestamp: "2026-03-22T10:00:00Z",
		Kind:      interactionKindMailIn,
		MessageID: "m-1",
		From:      "rose",
		Text:      "please review the patch",
	}
	appendInteractionLogForDir(tmp, entry)
	appendInteractionLogForDir(tmp, entry)

	entries, err := readInteractionLog(interactionLogPath(tmp), 0)
	if err != nil {
		t.Fatalf("readInteractionLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestFormatInteractionRecapRendersConversationLikeSummary(t *testing.T) {
	recap := formatInteractionRecap([]InteractionEntry{
		{Timestamp: "2026-03-22T10:00:00Z", Kind: interactionKindUser, Text: "please fix the continue UX"},
		{Timestamp: "2026-03-22T10:01:00Z", Kind: interactionKindAgent, Text: "I can do that with a small local recap."},
		{Timestamp: "2026-03-22T10:02:00Z", Kind: interactionKindChatIn, From: "rose", Text: "please keep it narrow"},
		{Timestamp: "2026-03-22T10:03:00Z", Kind: interactionKindMailOut, To: "henry", Subject: "review", Text: "please take a look"},
	}, 8)

	if !strings.Contains(recap, "Recent interactions") {
		t.Fatalf("expected heading, got %q", recap)
	}
	if strings.Contains(recap, "[10:00]") {
		t.Fatalf("did not expect timestamps, got %q", recap)
	}
	if !strings.Contains(recap, "> please fix the continue UX") {
		t.Fatalf("expected user line, got %q", recap)
	}
	if !strings.Contains(recap, "I can do that with a small local recap.") {
		t.Fatalf("expected agent line, got %q", recap)
	}
	if !strings.Contains(recap, "<- rose (chat): please keep it narrow") {
		t.Fatalf("expected chat line, got %q", recap)
	}
	if !strings.Contains(recap, "-> henry (mail): review — please take a look") {
		t.Fatalf("expected outbound mail line, got %q", recap)
	}
}

func TestFormatInteractionRecapWrapsCommLinesWithHangingIndent(t *testing.T) {
	recap := formatInteractionRecapStyled([]InteractionEntry{
		{
			Timestamp: "2026-03-22T10:02:00Z",
			Kind:      interactionKindMailIn,
			From:      "dave",
			Subject:   "Claude UX follow-up",
			Text:      "Merged to main. Good call on the streaming-safe approach for delta output.",
		},
	}, 8, false, 44)

	if !strings.Contains(recap, "<- dave (mail):") {
		t.Fatalf("expected comm prefix, got %q", recap)
	}
	if !strings.Contains(recap, "\n   ") {
		t.Fatalf("expected wrapped continuation indent, got %q", recap)
	}
}
