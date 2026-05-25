package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

func TestIDNamespacePrepareControllerCreatesLocalKeyAndDNSValueOnly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	out, err := executeIDNamespacePrepareController(idNamespacePrepareControllerOptions{
		Domain: "Acme.COM.",
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "prepared" {
		t.Fatalf("status=%q want prepared", out.Status)
	}
	if out.Domain != "acme.com" {
		t.Fatalf("domain=%q", out.Domain)
	}
	if out.DNSName != "_awid.acme.com" {
		t.Fatalf("dns name=%q", out.DNSName)
	}
	if !strings.Contains(out.DNSValue, "controller="+out.ControllerDID) {
		t.Fatalf("dns value %q does not contain controller %q", out.DNSValue, out.ControllerDID)
	}
	if strings.Contains(out.DNSValue, "registry=") {
		t.Fatalf("default registry should be omitted from DNS value: %q", out.DNSValue)
	}

	key, err := awconfig.LoadControllerKey("acme.com")
	if err != nil {
		t.Fatal(err)
	}
	gotDID := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	if gotDID != out.ControllerDID {
		t.Fatalf("controller key DID=%q want %q", gotDID, out.ControllerDID)
	}
	if info, err := os.Stat(out.ControllerKey); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("controller key mode=%#o want 0600", info.Mode().Perm())
	}

	metaData, err := os.ReadFile(out.ControllerMeta)
	if err != nil {
		t.Fatal(err)
	}
	var meta awconfig.ControllerMeta
	if err := yaml.Unmarshal(metaData, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Domain != "acme.com" || meta.ControllerDID != out.ControllerDID || meta.RegistryURL != awid.DefaultAWIDRegistryURL || meta.CreatedAt != now.Format(time.RFC3339) {
		t.Fatalf("meta=%+v output=%+v", meta, out)
	}
}

func TestIDNamespaceCheckTXTMatchesLocalControllerKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	prepared, err := executeIDNamespacePrepareController(idNamespacePrepareControllerOptions{
		Domain: "acme.com",
		Now:    func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := executeIDNamespaceCheckTXT(idNamespaceCheckTXTOptions{
		Domain: "acme.com",
		TXTResolver: staticTXTResolver{
			"_awid.acme.com": {prepared.DNSValue},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "matched" {
		t.Fatalf("status=%q want matched", out.Status)
	}
	if out.DNSController != prepared.ControllerDID || out.LocalController != prepared.ControllerDID {
		t.Fatalf("controller mismatch: out=%+v prepared=%+v", out, prepared)
	}
}

func TestIDNamespaceCheckTXTRejectsMismatchedLocalControllerKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	prepared, err := executeIDNamespacePrepareController(idNamespacePrepareControllerOptions{
		Domain: "acme.com",
		Now:    func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherDID := awid.ComputeDIDKey(otherPub)

	_, err = executeIDNamespaceCheckTXT(idNamespaceCheckTXTOptions{
		Domain: "acme.com",
		TXTResolver: staticTXTResolver{
			"_awid.acme.com": {idCreateDNSRecordValue(otherDID, awid.DefaultAWIDRegistryURL)},
		},
	})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match local controller") {
		t.Fatalf("unexpected error: %v; prepared=%+v", err, prepared)
	}
}

func TestIDCreateEOFExplainsNonInteractiveDNSVerification(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	workingDir := filepath.Join(tmp, "work")
	if err := os.MkdirAll(workingDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var prompt bytes.Buffer
	_, err := executeIDCreate(workingDir, idCreateOptions{
		Name:        "alice",
		Domain:      "acme.com",
		PromptIn:    strings.NewReader(""),
		PromptOut:   &prompt,
		TXTResolver: staticTXTResolver{},
		Now:         func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err == nil {
		t.Fatal("expected EOF guidance error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "aw id namespace check-txt --domain acme.com") {
		t.Fatalf("error did not mention check-txt: %v", err)
	}
	if !strings.Contains(prompt.String(), "Create this DNS TXT record before continuing") {
		t.Fatalf("prompt output missing TXT instructions: %q", prompt.String())
	}
	if _, statErr := os.Stat(filepath.Join(workingDir, ".aw", "identity.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("identity should not be persisted on EOF, stat err=%v", statErr)
	}
}

func TestIDCreateNonTerminalStdinDoesNotPrompt(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	workingDir := filepath.Join(tmp, "work")
	if err := os.MkdirAll(workingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := os.CreateTemp(tmp, "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, err := in.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	var prompt bytes.Buffer
	_, err = executeIDCreate(workingDir, idCreateOptions{
		Name:        "alice",
		Domain:      "acme.com",
		PromptIn:    in,
		PromptOut:   &prompt,
		TXTResolver: staticTXTResolver{},
		Now:         func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err == nil {
		t.Fatal("expected non-terminal guidance error")
	}
	if !strings.Contains(err.Error(), "aw id namespace check-txt --domain acme.com") {
		t.Fatalf("error did not mention check-txt: %v", err)
	}
	text := prompt.String()
	if !strings.Contains(text, "Create this DNS TXT record before continuing") {
		t.Fatalf("prompt output missing TXT instructions: %q", text)
	}
	if strings.Contains(text, "Verify this DNS TXT record now?") {
		t.Fatalf("non-terminal stdin should not receive interactive prompt: %q", text)
	}
	if _, statErr := os.Stat(filepath.Join(workingDir, ".aw", "identity.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("identity should not be persisted on non-terminal prompt refusal, stat err=%v", statErr)
	}
}

func TestIDNamespacePrepareControllerReusesExistingKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wantDID := awid.ComputeDIDKey(pub)
	if err := awconfig.SaveControllerKey("acme.com", key); err != nil {
		t.Fatal(err)
	}

	out, err := executeIDNamespacePrepareController(idNamespacePrepareControllerOptions{
		Domain:      "acme.com",
		RegistryURL: "https://registry.example.com",
		Now:         func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "existing" {
		t.Fatalf("status=%q want existing", out.Status)
	}
	if out.ControllerDID != wantDID {
		t.Fatalf("controller=%q want %q", out.ControllerDID, wantDID)
	}
	if !strings.Contains(out.DNSValue, "registry=https://registry.example.com;") {
		t.Fatalf("dns value missing registry override: %q", out.DNSValue)
	}
}
