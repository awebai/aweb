package main

import (
	"errors"
	"github.com/awebai/aw/awid"
	"strings"
	"testing"
)

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
		if err := protectedTerminal(protectedInputUnavailable, func() bool { return true }); errorCodeOf(err) != "protected_input_unavailable" {
			t.Fatalf("%s: err %v", name, err)
		}
	}
}

func TestProtectedTerminalRefusesWithoutAControllingTerminal(t *testing.T) {
	clearAgentMarkers(t)
	if err := protectedTerminal(protectedOutputUnavailable, func() bool { return false }); errorCodeOf(err) != "protected_output_unavailable" {
		t.Fatalf("err %v", err)
	}
}

func TestProtectedTerminalAdmitsAHumanAtATerminal(t *testing.T) {
	clearAgentMarkers(t)
	if err := protectedTerminal(protectedInputUnavailable, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
}

func TestHumanAndProtectedCommandsShareRuntimeRefusal(t *testing.T) {
	for _, marker := range agentRuntimeMarkers {
		t.Run(marker, func(t *testing.T) {
			clearAgentMarkers(t)
			t.Setenv(marker, "present")
			identityErr := humanAtTerminal()
			var certificateErr *awid.IDCertificateError
			if !errors.As(identityErr, &certificateErr) || certificateErr.Code != "human_approval_required" {
				t.Fatalf("identity refusal code lost: %v", identityErr)
			}
			protectedErr := protectedTerminal(protectedInputUnavailable, func() bool { t.Fatal("runtime refusal must precede terminal probing"); return false })
			if errorCodeOf(protectedErr) != "protected_input_unavailable" {
				t.Fatalf("protected refusal code lost: %v", protectedErr)
			}
			for _, err := range []error{identityErr, protectedErr} {
				if !strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "Run it yourself from an interactive terminal outside the agent runtime") {
					t.Fatalf("missing actionable refusal: %v", err)
				}
			}
		})
	}
}
