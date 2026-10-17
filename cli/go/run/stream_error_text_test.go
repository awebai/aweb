package run

import (
	"strings"
	"testing"

	awid "github.com/awebai/aw/awid"
)

func TestStreamErrorTextIsEscapedForTheTerminal(t *testing.T) {
	event, ok := ControlEventFromAgentEvent(awid.AgentEvent{Type: awid.AgentEventError, Text: "server says\x1b]0;title\a\u202e"})
	if !ok {
		t.Fatal("error event was not a control event")
	}
	if strings.ContainsAny(event.Text, "\x1b\a\u202e") {
		t.Fatalf("stream error carries raw control text: %q", event.Text)
	}
	if !strings.Contains(event.Text, `\x1b]0;title`) {
		t.Fatalf("stream error does not show the escape: %q", event.Text)
	}
}
