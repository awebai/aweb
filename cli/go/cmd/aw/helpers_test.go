package main

import (
	"strings"
	"testing"
)

func TestPromptIndexedChoiceRequiresNumberWhenNoDefault(t *testing.T) {
	t.Parallel()

	in := strings.NewReader("\n2\n")
	var out strings.Builder

	got, err := promptIndexedChoice("Role", []string{"coordinator", "developer"}, -1, in, &out)
	if err != nil {
		t.Fatalf("promptIndexedChoice: %v", err)
	}
	if got != "developer" {
		t.Fatalf("got %q, want developer", got)
	}
	text := out.String()
	if !strings.Contains(text, "1. coordinator") || !strings.Contains(text, "2. developer") {
		t.Fatalf("missing numbered role list:\n%s", text)
	}
	if !strings.Contains(text, "Role number: ") {
		t.Fatalf("missing numbered prompt without default:\n%s", text)
	}
	if !strings.Contains(text, "Enter a number between 1 and 2.") {
		t.Fatalf("missing retry hint for blank input:\n%s", text)
	}
}

func TestPromptIndexedChoiceRetriesUntilValidNumber(t *testing.T) {
	t.Parallel()

	in := strings.NewReader("x\n2\n")
	var out strings.Builder

	got, err := promptIndexedChoice("Role", []string{"coordinator", "developer"}, -1, in, &out)
	if err != nil {
		t.Fatalf("promptIndexedChoice: %v", err)
	}
	if got != "developer" {
		t.Fatalf("got %q, want developer", got)
	}
	if !strings.Contains(out.String(), "Enter a number between 1 and 2.") {
		t.Fatalf("missing retry hint:\n%s", out.String())
	}
}

func TestSelectRoleFromAvailableRolesRejectsUnknownExplicitRole(t *testing.T) {
	t.Parallel()

	_, err := selectRoleFromAvailableRoles("manager", []string{"coordinator", "developer"}, false, strings.NewReader(""), &strings.Builder{})
	if err == nil {
		t.Fatal("expected error for unknown role")
	}
	if !strings.Contains(err.Error(), `invalid role "manager"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
