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
	err := persistHostedIdentityState(hostedStatePersistence{WorkingDir: fixture.WorkingDir, SigningKey: fixture.SigningKey, Certificate: fixture.Certificate, Scope: localHostedIdentity})
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
	if err := persistHostedIdentityState(hostedStatePersistence{WorkingDir: fixture.WorkingDir, IdentityHome: fixture.Home, RegistryURL: "https://registry.example", SigningKey: fixture.SigningKey, Certificate: fixture.Certificate, DIDKey: fixture.DIDKey, DIDAW: fixture.DIDAW, MemberAddress: "example.test/probe", Scope: localHostedIdentity}); err != nil {
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

func TestHostedPersistenceGlobalStateUsesTheSameExplicitHome(t *testing.T) {
	fixture := newOnboardingPersistenceFixture(t)
	certificate, err := awid.SignTeamCertificate(fixture.SigningKey, awid.TeamCertificateFields{Team: "default:example.test", MemberDIDKey: fixture.DIDKey, MemberDIDAW: fixture.DIDAW, MemberAddress: "example.test/probe", Alias: "probe", IdentityScope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistHostedIdentityState(hostedStatePersistence{WorkingDir: fixture.WorkingDir, IdentityHome: fixture.Home, RegistryURL: "https://registry.example", SigningKey: fixture.SigningKey, Certificate: certificate, DIDKey: fixture.DIDKey, DIDAW: fixture.DIDAW, MemberAddress: "example.test/probe", Scope: globalHostedIdentity}); err != nil {
		t.Fatal(err)
	}
	state, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(fixture.Home.Root, "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if state.DID != fixture.DIDKey || state.StableID != fixture.DIDAW || state.Address != "example.test/probe" || state.IdentityScope != awid.IdentityModeGlobal {
		t.Fatalf("incorrect global identity state: %+v", state)
	}
	if _, err := os.Stat(filepath.Join(fixture.WorkingDir, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("wrote implicit home: %v", err)
	}
}

func TestHostedPersistenceRejectsMissingScopeBeforeWriting(t *testing.T) {
	fixture := newOnboardingPersistenceFixture(t)
	err := persistHostedIdentityState(hostedStatePersistence{WorkingDir: fixture.WorkingDir, IdentityHome: fixture.Home, SigningKey: fixture.SigningKey, Certificate: fixture.Certificate})
	if err == nil || !strings.Contains(err.Error(), "Select local or global identity scope and retry") {
		t.Fatalf("missing scope refusal: %v", err)
	}
	if _, err := os.Stat(fixture.Home.Root); !os.IsNotExist(err) {
		t.Fatalf("wrote credentials before validating scope: %v", err)
	}
}
