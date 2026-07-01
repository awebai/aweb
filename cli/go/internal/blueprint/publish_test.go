package blueprint

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractProfilePayloadNamedProfile(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)

	pub, err := ExtractProfilePayload(root, "coordinator")
	if err != nil {
		t.Fatalf("ExtractProfilePayload: %v", err)
	}
	if pub.ProfileRef != "coordinator" || pub.SourceBlueprintRef != "aweb.engineering" {
		t.Fatalf("unexpected provenance: %+v", pub)
	}
	if pub.ProfileDigest == "" {
		t.Fatalf("missing profile digest")
	}
	byPath := map[string]LibraryProfilePayloadFile{}
	for _, f := range pub.Files {
		if strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, "profiles/") {
			t.Fatalf("path not profile-relative: %s", f.Path)
		}
		sum := sha256.Sum256([]byte(f.ContentUTF8))
		if f.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("sha256 mismatch for %s", f.Path)
		}
		byPath[f.Path] = f
	}
	for _, want := range []string{"profile.yaml", "instructions.md", "skills/coordinate/SKILL.md", "artifacts/status.sh"} {
		if _, ok := byPath[want]; !ok {
			t.Fatalf("payload missing %s", want)
		}
	}
}

func TestExtractProfilePayloadDefaultsToSoleProfile(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)

	pub, err := ExtractProfilePayload(root, "")
	if err != nil {
		t.Fatalf("ExtractProfilePayload sole: %v", err)
	}
	if pub.ProfileRef != "coordinator" {
		t.Fatalf("sole profile not defaulted: %s", pub.ProfileRef)
	}
}

func TestExtractProfilePayloadRequiresRefWhenMultiple(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	// add a second profile so selection is ambiguous.
	writeFile(t, filepath.Join(root, "blueprint.yaml"), `id: aweb.engineering
name: Engineering AI Team Starter Blueprint
version: 0.1.0
summary: Two profiles.
description: A starter blueprint.
profiles:
  - id: coordinator
    default_count: 1
    min: 1
    max: 1
    runtime_hints: [claude-code]
  - id: reviewer
    default_count: 1
    min: 1
    max: 1
    runtime_hints: [claude-code]
runtime_hints: [claude-code]
expected_apps: [library, tasks]
first_mission_examples:
  - Review this repo.
`)
	writeFile(t, filepath.Join(root, "profiles/reviewer/profile.yaml"), `id: reviewer
name: Reviewer
version: 0.1.0
mission: Review changes and keep quality high.
accepted_work: [review]
instructions: instructions.md
runtime_assumptions: [local shell, git checkout]
memory_policy:
  mode: reviewed-learning
  proposal_target: library
expected_apps: [library, tasks]
`)
	writeFile(t, filepath.Join(root, "profiles/reviewer/instructions.md"), "Review carefully.\n")

	if _, err := ExtractProfilePayload(root, ""); err == nil || !strings.Contains(err.Error(), "--profile is required") {
		t.Fatalf("expected --profile-required error, got %v", err)
	}
	pub, err := ExtractProfilePayload(root, "reviewer")
	if err != nil {
		t.Fatalf("select reviewer: %v", err)
	}
	if pub.ProfileRef != "reviewer" {
		t.Fatalf("selected ref=%s", pub.ProfileRef)
	}
}
