package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

func TestHumanActionTextCannotControlTheTerminal(t *testing.T) {
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	response := &handoff.Response{Body: []byte("status\x1b[2J\u202ehidden\nnext line")}
	if err := printActionResponse(command, response, nil); err != nil {
		t.Fatal(err)
	}
	want := "status\\x1b[2J\\u202ehidden\nnext line"
	if output.String() != want {
		t.Fatalf("unsafe action output: got %q, want %q", output.String(), want)
	}
}

func TestHumanActionJSONEscapesTerminalControlsWithoutChangingValues(t *testing.T) {
	value := map[string]string{"status": "safe\u202ehidden\u200b\x1b[2J"}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	if err := printActionResponse(command, &handoff.Response{Body: raw}, nil); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"\u202e", "\u200b", "\x1b"} {
		if strings.Contains(output.String(), unsafe) {
			t.Fatalf("terminal control emitted in %q", output.String())
		}
	}
	var decoded map[string]string
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["status"] != value["status"] {
		t.Fatalf("JSON value changed: %q", decoded["status"])
	}
}

func TestHumanActionRejectsUnseparableProtectedOutput(t *testing.T) {
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	err := printActionResponse(command, &handoff.Response{Body: []byte("secret")}, []string{"/secret"})
	if err == nil || !strings.Contains(err.Error(), "terminal-only") {
		t.Fatalf("wanted protected-output refusal, got %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("protected output escaped to stdout")
	}
}

func TestProtectedActionValuesUseTheSameTerminalEscaping(t *testing.T) {
	var output bytes.Buffer
	values := []terminalValue{{Pointer: "/token\u202e", Value: "secret\x1b[2J\nnext"}}
	if err := writeTerminalValues(&output, values); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "/token\\u202e: secret\\x1b[2J\\x0anext\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestProtectedActionValuesReportEncodingFailures(t *testing.T) {
	var output bytes.Buffer
	if err := writeTerminalValues(&output, []terminalValue{{Pointer: "/token", Value: make(chan int)}}); err == nil {
		t.Fatal("unencodable protected output was silently discarded")
	}
	if output.Len() != 0 {
		t.Fatal("failed protected output produced bytes")
	}
}
