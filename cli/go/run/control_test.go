package run

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testWriteCloser struct {
	*bytes.Buffer
}

func (t testWriteCloser) Close() error { return nil }

func TestParseControlSubmissionHelp(t *testing.T) {
	event := ParseControlSubmission("/help")
	if event.Type != ControlHelp {
		t.Fatalf("expected ControlHelp, got %q", event.Type)
	}
}

func TestParseControlSubmissionRejectsUnknownSlashCommand(t *testing.T) {
	event := ParseControlSubmission("/foo")
	if event.Type != ControlUnknownCommand {
		t.Fatalf("expected ControlUnknownCommand, got %q", event.Type)
	}
	if event.Text != "/foo" {
		t.Fatalf("expected text '/foo', got %q", event.Text)
	}
}

func TestParseControlSubmissionPassesRegularText(t *testing.T) {
	event := ParseControlSubmission("hello world")
	if event.Type != ControlPrompt {
		t.Fatalf("expected ControlPrompt, got %q", event.Type)
	}
	if event.Text != "hello world" {
		t.Fatalf("expected text 'hello world', got %q", event.Text)
	}
}

func TestParseControlSubmissionProviderInput(t *testing.T) {
	event := ParseControlSubmission("/provider y")
	if event.Type != ControlProviderInput {
		t.Fatalf("expected ControlProviderInput, got %q", event.Type)
	}
	if event.Text != "y" {
		t.Fatalf("expected text 'y', got %q", event.Text)
	}
}

func TestHelpEventPrintsCommands(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{}, &out)
	st := &state{}

	loop.applyControlEvent(ControlEvent{Type: ControlHelp}, st, false, nil)

	output := out.String()
	for _, cmd := range []string{"/wait", "/stop", "/provider", "/autofeed", "/quit", "/help"} {
		if !strings.Contains(output, cmd) {
			t.Errorf("help output missing %q, got %q", cmd, output)
		}
	}
}

func TestUnknownCommandEventPrintsError(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{}, &out)
	st := &state{}

	loop.applyControlEvent(ControlEvent{Type: ControlUnknownCommand, Text: "/foo"}, st, false, nil)

	output := out.String()
	if !strings.Contains(output, "unknown command: /foo") {
		t.Fatalf("expected unknown command error, got %q", output)
	}
	if !strings.Contains(output, "/help") {
		t.Fatalf("expected /help hint in error, got %q", output)
	}
}

func TestUnknownSlashPathQueuesAttachmentPrompt(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{}, &out)
	st := &state{}

	dir := t.TempDir()
	path := filepath.Join(dir, "image.png")
	if err := os.WriteFile(path, []byte("png"), 0o644); err != nil {
		t.Fatalf("write image file: %v", err)
	}

	loop.applyControlEvent(ControlEvent{Type: ControlUnknownCommand, Text: path}, st, false, nil)

	if got := out.String(); strings.Contains(got, "unknown command") {
		t.Fatalf("did not expect unknown command output, got %q", got)
	}
	if st.NextPrompt != "User attached image: "+path {
		t.Fatalf("unexpected queued prompt %q", st.NextPrompt)
	}
	if len(st.NextImagePaths) != 1 || st.NextImagePaths[0] != path {
		t.Fatalf("unexpected queued image paths %#v", st.NextImagePaths)
	}
}

func TestQueuePromptTextPreservesImageOnlyInput(t *testing.T) {
	loop := NewLoop(fakeProvider{}, &bytes.Buffer{})
	st := &state{}

	loop.queuePromptText(st, "", []string{"/tmp/image.png"}, false)

	if st.NextPrompt != "User attached image: /tmp/image.png" {
		t.Fatalf("unexpected queued prompt %q", st.NextPrompt)
	}
	if len(st.NextImagePaths) != 1 || st.NextImagePaths[0] != "/tmp/image.png" {
		t.Fatalf("unexpected queued image paths %#v", st.NextImagePaths)
	}
}

func TestProviderInputEventWritesToActiveProvider(t *testing.T) {
	var out bytes.Buffer
	var stdin bytes.Buffer
	loop := NewLoop(fakeProvider{}, &out)
	st := &state{
		ProviderInput: &providerInputState{},
	}
	st.ProviderInput.SetWriter(testWriteCloser{Buffer: &stdin})

	loop.applyControlEvent(ControlEvent{Type: ControlProviderInput, Text: "y"}, st, true, nil)

	if got := stdin.String(); got != "y\n" {
		t.Fatalf("expected provider stdin write, got %q", got)
	}
	if got := out.String(); !strings.Contains(got, "sent provider input: y") {
		t.Fatalf("expected confirmation output, got %q", got)
	}
}
