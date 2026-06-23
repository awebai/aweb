package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAgentRefJSON(t *testing.T, home string) {
	t.Helper()
	dir := filepath.Join(home, ".aw", "profile")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "profile_digest": "sha256:profdig",
  "profile_ref": "frontend-author",
  "profile_version": "0.1.0",
  "source_blueprint_digest": "sha256:bpdig",
  "source_blueprint_ref": "aweb.design",
  "source_blueprint_version": "0.1.0"
}`
	if err := os.WriteFile(filepath.Join(dir, "ref.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAgentProfileShowText(t *testing.T) {
	home := t.TempDir()
	writeAgentRefJSON(t, home)
	agentHomeFlag = home
	defer func() { agentHomeFlag = "" }()

	var buf bytes.Buffer
	agentProfileShowCmd.SetOut(&buf)
	if err := runAgentProfileShow(agentProfileShowCmd, []string{"designer"}); err != nil {
		t.Fatalf("show: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"designer", "aweb.design@0.1.0", "frontend-author@0.1.0", "sha256:profdig", "sha256:bpdig"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestAgentProfileShowJSON(t *testing.T) {
	home := t.TempDir()
	writeAgentRefJSON(t, home)
	agentHomeFlag = home
	jsonFlag = true
	defer func() { agentHomeFlag = ""; jsonFlag = false }()

	var buf bytes.Buffer
	agentProfileShowCmd.SetOut(&buf)
	if err := runAgentProfileShow(agentProfileShowCmd, []string{"designer"}); err != nil {
		t.Fatalf("show --json: %v", err)
	}
	var ref recordedProfileRef
	if err := json.Unmarshal(buf.Bytes(), &ref); err != nil {
		t.Fatalf("output is not the ref JSON: %v\n%s", err, buf.String())
	}
	if ref.SourceBlueprintRef != "aweb.design" || ref.ProfileRef != "frontend-author" || ref.ProfileVersion != "0.1.0" {
		t.Fatalf("decoded ref wrong: %+v", ref)
	}
}

func TestAgentProfileShowMissing(t *testing.T) {
	home := t.TempDir() // no ref.json
	agentHomeFlag = home
	defer func() { agentHomeFlag = "" }()
	err := runAgentProfileShow(agentProfileShowCmd, []string{"designer"})
	if err == nil || !strings.Contains(err.Error(), "no recorded profile") {
		t.Fatalf("want 'no recorded profile' error, got %v", err)
	}
}
