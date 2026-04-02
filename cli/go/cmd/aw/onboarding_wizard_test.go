package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPadSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		slug   string
		minLen int
		want   string
	}{
		{"a1", 3, "a1x"},
		{"ab", 3, "abx"},
		{"a", 3, "axx"},
		{"abc", 3, "abc"},
		{"abcd", 3, "abcd"},
		{"", 3, "xxx"},
	}
	for _, tt := range tests {
		if got := padSlug(tt.slug, tt.minLen); got != tt.want {
			t.Errorf("padSlug(%q, %d) = %q, want %q", tt.slug, tt.minLen, got, tt.want)
		}
	}
}

func TestPromptProjectSlugRejectsShortInput(t *testing.T) {
	t.Parallel()
	// First input "ab" is too short, second input "abc" should be accepted.
	in := strings.NewReader("ab\nabc\n")
	var out bytes.Buffer
	got, err := promptProjectSlug("default", in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc" {
		t.Fatalf("got %q, want %q", got, "abc")
	}
	if !strings.Contains(out.String(), "at least 3 characters") {
		t.Fatalf("expected validation message, got %q", out.String())
	}
}

func TestPromptProjectSlugUsesDefault(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("\n")
	var out bytes.Buffer
	got, err := promptProjectSlug("myproject", in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "myproject" {
		t.Fatalf("got %q, want %q", got, "myproject")
	}
}

func TestPromptProjectSlugAcceptsUserInput(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("custom-project\n")
	var out bytes.Buffer
	got, err := promptProjectSlug("default-val", in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "custom-project" {
		t.Fatalf("got %q, want %q", got, "custom-project")
	}
}

func TestPromptIdentityLifetimeShowsDescriptions(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("\n") // accept default (ephemeral)
	var out bytes.Buffer
	permanent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permanent {
		t.Fatal("expected ephemeral (default), got permanent")
	}
	output := out.String()
	if !strings.Contains(output, "workspace-bound") {
		t.Fatalf("expected ephemeral description, got %q", output)
	}
	if !strings.Contains(output, "public addresses") {
		t.Fatalf("expected permanent description, got %q", output)
	}
	if strings.Contains(output, "number") {
		t.Fatalf("prompt should not say 'number', got %q", output)
	}
}

func TestPromptIdentityLifetimePermanent(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("2\n")
	var out bytes.Buffer
	permanent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !permanent {
		t.Fatal("expected permanent, got ephemeral")
	}
}

func TestWizardUsesPromptedProjectSlug(t *testing.T) {
	t.Parallel()
	// Verify that promptProjectSlug output is used (not the pre-set default)
	// and that the slug is sanitized before being passed downstream.
	in := strings.NewReader("My Project!\n")
	var out bytes.Buffer
	got, err := promptProjectSlug("old-default", in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "my-project" {
		t.Fatalf("expected sanitized slug %q, got %q", "my-project", got)
	}
}

func TestWizardShortDirNameGetsPadded(t *testing.T) {
	t.Parallel()
	// When directory name is "a1", the default should be padded to "a1x"
	slug := padSlug(sanitizeSlug("a1"), minProjectSlugLength)
	if slug != "a1x" {
		t.Fatalf("expected %q, got %q", "a1x", slug)
	}
}
