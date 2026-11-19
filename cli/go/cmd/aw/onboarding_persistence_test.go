package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type onboardingPersistenceFixture struct {
	WorkingDir  string
	Home        awconfig.IdentityHome
	SigningKey  ed25519.PrivateKey
	Certificate *awid.TeamCertificate
	DIDKey      string
	DIDAW       string
}

func newOnboardingPersistenceFixture(t *testing.T) onboardingPersistenceFixture {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	cert, err := awid.SignTeamCertificate(key, awid.TeamCertificateFields{Team: "default:example.test", MemberDIDKey: did, Alias: "probe", IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	return onboardingPersistenceFixture{WorkingDir: t.TempDir(), Home: awconfig.IdentityHome{Root: filepath.Join(t.TempDir(), "selected-home"), Source: awconfig.IdentityHomeFlag}, SigningKey: key, Certificate: cert, DIDKey: did, DIDAW: awid.ComputeStableID(pub)}
}

func TestHostedPersistenceRequiresExplicitIdentityHomeBeforeWriting(t *testing.T) {
	fixture := newOnboardingPersistenceFixture(t)
	err := persistGuidedHostedState(fixture.WorkingDir, "https://registry.example", fixture.SigningKey, fixture.Certificate, fixture.DIDKey, fixture.DIDAW, "example.test/probe", false, "")
	if err == nil || !strings.Contains(err.Error(), "Select an identity home and retry") {
		t.Fatalf("missing required-home refusal: %v", err)
	}
	for _, name := range []string{".aw", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(fixture.WorkingDir, name)); !os.IsNotExist(err) {
			t.Fatalf("wrote before identity-home validation: %s (%v)", name, err)
		}
	}
}

func TestHostedPersistenceWritesOnlyExplicitLocalHome(t *testing.T) {
	fixture := newOnboardingPersistenceFixture(t)
	if err := persistGuidedHostedState(fixture.WorkingDir, "https://registry.example", fixture.SigningKey, fixture.Certificate, fixture.DIDKey, fixture.DIDAW, "example.test/probe", false, fixture.Home.Root); err != nil {
		t.Fatal(err)
	}
	key, err := awid.LoadSigningKey(filepath.Join(fixture.Home.Root, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, fixture.SigningKey) {
		t.Fatal("wrong signing key persisted")
	}
	cert, err := awid.LoadTeamCertificate(filepath.Join(fixture.Home.Root, awconfig.TeamCertificateRelativePath(fixture.Certificate.Team)))
	if err != nil {
		t.Fatal(err)
	}
	if cert.MemberDIDKey != fixture.DIDKey {
		t.Fatal("wrong team certificate persisted")
	}
	if _, err := os.Stat(filepath.Join(fixture.WorkingDir, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("wrote implicit home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.Home.Root, "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("local persistence wrote global identity state: %v", err)
	}
}
