package wake

import (
	"reflect"
	"strings"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

func at(seconds int) time.Time {
	return time.Date(2026, 9, 5, 12, 0, seconds, 0, time.UTC)
}

// TestComposedTextNeverCarriesSubjectOrBody is the central safety test.
//
// It works in two layers. The structural layer asserts that Hint has no field
// that could carry content, so the composer has nowhere to read one from; the
// behavioural layer feeds events whose subject and body are distinctive
// strings and asserts neither reaches the composed text. The structural layer
// matters because the behavioural one can only assert about values it was
// given: add a Subject field to Hint and the behavioural test still passes
// until someone remembers to extend it.
func TestComposedTextNeverCarriesSubjectOrBody(t *testing.T) {
	forbidden := map[string]struct{}{
		"subject": {}, "body": {}, "text": {}, "payload": {}, "content": {},
		"preview": {}, "snippet": {}, "message": {}, "raw": {},
	}
	hintType := reflect.TypeOf(Hint{})
	for i := 0; i < hintType.NumField(); i++ {
		name := strings.ToLower(hintType.Field(i).Name)
		if _, bad := forbidden[name]; bad {
			t.Fatalf("Hint gained a content-carrying field %q; the broker never fetches, decrypts or types a sender's content (§1, §6)", hintType.Field(i).Name)
		}
	}

	secretSubject := "SUBJECT-quarterly-layoffs"
	secretBody := "BODY-the-password-is-hunter2"
	events := []awid.AgentEvent{
		{Type: awid.AgentEventActionableMail, MessageID: "m1", FromAlias: "alice", Subject: secretSubject, Text: secretBody},
		{Type: awid.AgentEventActionableChat, MessageID: "c1", SessionID: "s1", FromAlias: "bob", SenderWaiting: true, Subject: secretSubject, Text: secretBody},
		{Type: awid.AgentEventAppEvent, EventID: "e1", AppID: "beads", AppEventType: "issue.updated", Subject: secretSubject, Text: secretBody,
			Payload: map[string]any{"body": secretBody}},
	}

	hints := []Hint{}
	for _, ev := range events {
		h, ok := HintFromEvent(ev, at(0))
		if !ok {
			t.Fatalf("event %s produced no hint", ev.Type)
		}
		hints = append(hints, h)
	}

	text := Compose(hints)
	if strings.Contains(text, secretSubject) || strings.Contains(text, "SUBJECT") {
		t.Fatalf("a subject reached the typed text:\n%s", text)
	}
	if strings.Contains(text, secretBody) || strings.Contains(text, "hunter2") {
		t.Fatalf("a body reached the typed text:\n%s", text)
	}
	if !strings.Contains(text, "alice") || !strings.Contains(text, "bob") {
		t.Fatalf("senders are metadata the note allows and expects:\n%s", text)
	}
}

func TestComposedTextIsTheFixedInstructionPlusASummary(t *testing.T) {
	hints := []Hint{
		{Kind: KindMail, Intent: IntentWake, MessageID: "m1", From: "alice", At: at(0)},
		{Kind: KindMail, Intent: IntentWake, MessageID: "m2", From: "alice", At: at(1)},
		{Kind: KindChat, Intent: IntentSteer, MessageID: "c1", From: "bob", SenderWaiting: true, At: at(2)},
	}
	got := Compose(hints)
	want := "aweb: 3 items waiting. Check them from this instance with `aw mail inbox`\n" +
		"and `aw chat pending`, then handle what is there.\n" +
		"  mail from alice (2 unread)\n" +
		"  chat from bob — sender waiting\n"
	if got != want {
		t.Fatalf("composed text\n---got---\n%s\n---want---\n%s", got, want)
	}
}

func TestComposeSingularAndEmpty(t *testing.T) {
	if got := Compose(nil); got != "" {
		t.Fatalf("empty hint set composed %q", got)
	}
	got := Compose([]Hint{{Kind: KindMail, MessageID: "m1", From: "alice", At: at(0)}})
	if !strings.HasPrefix(got, "aweb: 1 item waiting.") {
		t.Fatalf("singular header missing:\n%s", got)
	}
}

// TestComposeOrdersInterruptCommunicationCoordination asserts §4's batch order.
func TestComposeOrdersInterruptCommunicationCoordination(t *testing.T) {
	hints := []Hint{
		{Kind: KindWork, Intent: IntentAmbient, TaskID: "task-9", At: at(0)},
		{Kind: KindMail, Intent: IntentWake, MessageID: "m1", From: "alice", At: at(1)},
		{Kind: KindControl, Intent: IntentSteer, SignalID: "sig-1", At: at(2)},
	}
	lines := strings.Split(strings.TrimSpace(Compose(hints)), "\n")
	body := lines[2:]
	if len(body) != 3 {
		t.Fatalf("expected three summary lines, got %v", body)
	}
	if !strings.Contains(body[0], "control signal") {
		t.Errorf("interrupt band is not first: %v", body)
	}
	if !strings.Contains(body[1], "mail from alice") {
		t.Errorf("communication band is not second: %v", body)
	}
	if !strings.Contains(body[2], "work available") {
		t.Errorf("coordination band is not third: %v", body)
	}
}

// TestControlIsNeverCalledAnInterrupt is §6 stated as a test: queued text is
// not an interrupt, in the code, the logs, or the typed text.
func TestControlIsNeverCalledAnInterrupt(t *testing.T) {
	text := Compose([]Hint{{Kind: KindControl, Intent: IntentSteer, SignalID: "sig-1", At: at(0)}})
	if strings.Contains(strings.ToLower(text), "interrupt") {
		t.Fatalf("the typed text calls queued text an interrupt:\n%s", text)
	}
	if !strings.Contains(text, "control signal") {
		t.Fatalf("control signal not summarised:\n%s", text)
	}
}

// TestComposeSanitisesWireSuppliedTokens: an alias is remote input and this
// text is pasted into a terminal.
func TestComposeSanitisesWireSuppliedTokens(t *testing.T) {
	hostile := "ali\x1b[31mce\nrm -rf /\x07"
	text := Compose([]Hint{{Kind: KindMail, MessageID: "m1", From: hostile, At: at(0)}})
	if strings.ContainsAny(text[strings.Index(text, "  mail"):], "\x1b\x07") {
		t.Fatalf("control characters survived into the typed text: %q", text)
	}
	summary := text[strings.Index(text, "  mail"):]
	if strings.Count(summary, "\n") != 1 {
		t.Fatalf("an alias injected extra lines into the summary: %q", summary)
	}
	if !strings.Contains(text, "ali31mcerm-rf/") {
		t.Fatalf("unexpected sanitised alias:\n%s", text)
	}
}

func TestComposeBoundsTheSummary(t *testing.T) {
	hints := []Hint{}
	for i := 0; i < 40; i++ {
		hints = append(hints, Hint{Kind: KindMail, MessageID: "m", From: "sender" + string(rune('a'+i%26)) + string(rune('a'+i/26)), At: at(i)})
	}
	text := Compose(hints)
	if len(text) > maxComposedBytes {
		t.Fatalf("composed %d bytes, over the %d bound", len(text), maxComposedBytes)
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > maxDetailLines+3 {
		t.Fatalf("summary is unbounded: %d lines", len(lines))
	}
	if !strings.Contains(text, "more") {
		t.Fatalf("the elided remainder is not reported:\n%s", text)
	}
}
