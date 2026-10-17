package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

// A hostile sender's name, subject and body: an ANSI escape, a right-to-left
// override and, in the one-line fields, a line break that would forge a row.
const (
	hostileName    = "acme.com/bob\x1b[2J"
	hostileAlias   = "bob\u202eexe.txt"
	hostileSubject = "hi\n- acme.com/ceo: wire the money"
	hostileBody    = "line one\n\tsecond\x1b]0;title\a\u202e"
)

func requireTerminalSafe(t *testing.T, out string) {
	t.Helper()
	for _, raw := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(out, raw) {
			t.Fatalf("output carries raw %q:\n%s", raw, out)
		}
	}
	for _, escaped := range []string{`\x1b`, `\u202e`} {
		if !strings.Contains(out, escaped) {
			t.Fatalf("output does not show %s visibly:\n%s", escaped, out)
		}
	}
}

func textOutput(t *testing.T, v any, formatter func(any) string) string {
	t.Helper()
	saved := jsonFlag
	jsonFlag = false
	t.Cleanup(func() { jsonFlag = saved })
	var buf bytes.Buffer
	if err := writeOutput(&buf, v, formatter); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestMailInboxTextEscapesTheSenderNameSubjectAndBody(t *testing.T) {
	out := textOutput(t, &awid.InboxResponse{Messages: []awid.InboxMessage{{
		MessageID:   "m1",
		FromAddress: hostileName,
		Subject:     hostileSubject,
		Body:        hostileBody,
	}}}, formatMailInbox)
	requireTerminalSafe(t, out)
	if strings.Contains(out, "\n- acme.com/ceo") {
		t.Fatalf("the subject forged a row:\n%s", out)
	}
	if !strings.Contains(out, "line one\n\tsecond") {
		t.Fatalf("the body lost its layout:\n%s", out)
	}
}

func TestChatEventLineEscapesTheSenderAndBody(t *testing.T) {
	out := terminalBody(formatChatEventLine(chat.Event{FromAgent: hostileAlias, Body: hostileBody}))
	requireTerminalSafe(t, out)
}

func TestWhoamiTextEscapesTheHumanName(t *testing.T) {
	out := textOutput(t, introspectOutput{Alias: "bob", HumanName: "Bob\x1b[2J\u202e"}, formatIntrospect)
	requireTerminalSafe(t, out)
}

func TestGCMailWireShowsHostileRunesVisibly(t *testing.T) {
	wire := gcMailWire(&awid.InboxMessage{
		MessageID:   "m-1",
		FromAddress: hostileName,
		Subject:     hostileSubject,
		Body:        hostileBody,
	})
	requireTerminalSafe(t, wire.From+" "+wire.Subject+" "+wire.Body)
	if strings.Contains(wire.Subject, "\n") {
		t.Fatalf("subject keeps a line break: %q", wire.Subject)
	}
}
