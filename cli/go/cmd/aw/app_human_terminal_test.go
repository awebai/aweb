package main

import "testing"

func clearAgentMarkers(t *testing.T) {
	t.Helper()
	for _, name := range agentRuntimeMarkers {
		t.Setenv(name, "")
	}
}

func TestProtectedTerminalRefusesUnderAnAgentRuntime(t *testing.T) {
	for _, name := range agentRuntimeMarkers {
		clearAgentMarkers(t)
		t.Setenv(name, "1")
		if err := protectedTerminal("protected_input_unavailable", func() bool { return true }); errorCodeOf(err) != "protected_input_unavailable" {
			t.Fatalf("%s: err %v", name, err)
		}
	}
}

func TestProtectedTerminalRefusesWithoutAControllingTerminal(t *testing.T) {
	clearAgentMarkers(t)
	if err := protectedTerminal("protected_output_unavailable", func() bool { return false }); errorCodeOf(err) != "protected_output_unavailable" {
		t.Fatalf("err %v", err)
	}
}

func TestProtectedTerminalAdmitsAHumanAtATerminal(t *testing.T) {
	clearAgentMarkers(t)
	if err := protectedTerminal("protected_input_unavailable", func() bool { return true }); err != nil {
		t.Fatal(err)
	}
}
