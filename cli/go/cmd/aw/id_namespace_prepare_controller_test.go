package main

import (
	"crypto/ed25519"
	"os"
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
