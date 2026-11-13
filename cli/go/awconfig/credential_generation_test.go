package awconfig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

var (
	installA = CredentialOperation{Command: "install-cert", Intent: "intent-a"}
	installB = CredentialOperation{Command: "install-cert", Intent: "intent-b"}
	importA  = CredentialOperation{Command: "parent-import", Intent: "intent-a"}
)

// credentialHome is an identity home with one membership whose certificate is
// at certPath, and a second membership of another team.
func credentialHome(t *testing.T, certPath string) string {
	t.Helper()
	home := t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	write("identity.yaml", "did: "+awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))+"\n")
	write("teams.yaml", "active_team: backend:example.com\nmemberships:\n  - team_id: backend:example.com\n    cert_path: "+certPath+
		"\n  - team_id: frontend:example.com\n    cert_path: team-certs/frontend__example.com.pem\n")
	write("workspace.yaml", "aweb_url: https://app.example.com\nmemberships:\n  - team_id: backend:example.com\n    cert_path: "+certPath+
		"\n    role_name: builder\n")
	write(certPath, "backend certificate\n")
	write("team-certs/frontend__example.com.pem", "frontend certificate\n")
	return home
}

func projectionOf(t *testing.T, home string) string {
	t.Helper()
	capture, err := CaptureCredentials(home)
	if err != nil {
		t.Fatal(err)
	}
	return capture.Projection
}

func writeFile(t *testing.T, home, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, filepath.FromSlash(rel)), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func updateWith(home string, op CredentialOperation, rel, content string) error {
	return UpdateCredentials(home, op, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(home, filepath.FromSlash(rel)), []byte(content), 0o600)
	})
}

func assertState(t *testing.T, home string, generation int64, incomplete bool) {
	t.Helper()
	state, err := ReadCredentialState(home)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != generation || (state.Marker != nil) != incomplete {
		t.Fatalf("generation %d marker %+v, want %d incomplete %v", state.Generation, state.Marker, generation, incomplete)
	}
}

// The projection covers every membership's certificate, wherever its
// cert_path names it, and the credential fields, not workspace metadata.
func TestTheProjectionCoversEveryMembershipButNotWorkspaceMetadata(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	base := projectionOf(t, home)
	if again := projectionOf(t, home); again != base {
		t.Fatal("the projection is not stable")
	}
	writeFile(t, home, "workspace.yaml", "aweb_url: https://app.example.com\nmemberships:\n  - team_id: backend:example.com\n    cert_path: team-cert.pem\n    role_name: reviewer\n")
	if projectionOf(t, home) != base {
		t.Fatal("a role name changed the projection")
	}
	for name, change := range map[string][2]string{
		"the legacy certificate":     {"team-cert.pem", "another backend certificate\n"},
		"another team's certificate": {"team-certs/frontend__example.com.pem", "another frontend certificate\n"},
		"the signing key":            {"signing.key", "other-key\n"},
		"the installed chain":        {"id-chain.json", "{}"},
		"the active team":            {"teams.yaml", "active_team: frontend:example.com\nmemberships:\n  - team_id: backend:example.com\n    cert_path: team-cert.pem\n  - team_id: frontend:example.com\n    cert_path: team-certs/frontend__example.com.pem\n"},
		"the workspace's service":    {"workspace.yaml", "aweb_url: https://other.example.com\nmemberships:\n  - team_id: backend:example.com\n    cert_path: team-cert.pem\n    role_name: reviewer\n"},
	} {
		home := credentialHome(t, "team-cert.pem")
		before := projectionOf(t, home)
		writeFile(t, home, change[0], change[1])
		if projectionOf(t, home) == before {
			t.Errorf("%s did not change the projection", name)
		}
	}
}

func TestACapturedHomeIsAPrivateReadOnlyCopyOfItsInputs(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	capture, err := CaptureCredentials(home)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "capture")
	if err := capture.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"identity.yaml", "signing.key", "teams.yaml", "workspace.yaml", "team-cert.pem", "team-certs/frontend__example.com.pem"} {
		want, _ := os.ReadFile(filepath.Join(home, filepath.FromSlash(rel)))
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		info, statErr := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || statErr != nil || !bytes.Equal(got, want) || info.Mode().Perm() != 0o400 {
			t.Errorf("%s: %v %v %v", rel, err, statErr, info)
		}
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("capture dir %v %v", info, err)
	}
	if again, err := CaptureCredentials(dir); err != nil || again.Projection != capture.Projection {
		t.Fatalf("the copy projects %v, want %s (%v)", again, capture.Projection, err)
	}
}

func TestACompletedUpdatePublishesTheNextGenerationAndItsProjection(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	if err := updateWith(home, installA, "team-cert.pem", "new backend certificate\n"); err != nil {
		t.Fatal(err)
	}
	assertState(t, home, 1, false)
	state, _ := ReadCredentialState(home)
	if state.Projection != projectionOf(t, home) {
		t.Fatal("the manifest does not name the home's projection")
	}
	if err := updateWith(home, importA, "id-chain.json", "{}"); err != nil {
		t.Fatal(err)
	}
	assertState(t, home, 2, false)
}

func TestARefusalBeforeWritingPublishesNothing(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	refused := errors.New("refused")
	if err := UpdateCredentials(home, installA, func(func() error) error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("err %v", err)
	}
	assertState(t, home, 0, false)
}

// An interrupted update is recovered only by the same operation; any other
// operation, even under the same command, refuses and writes nothing.
func TestAnInterruptedUpdateIsRecoveredOnlyByTheSameOperation(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	failed := errors.New("half written")
	err := UpdateCredentials(home, installA, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeFile(t, home, "team-cert.pem", "half\n")
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatalf("err %v", err)
	}
	assertState(t, home, 0, true)
	for _, other := range []CredentialOperation{installB, importA} {
		before := projectionOf(t, home)
		if err := updateWith(home, other, "id-chain.json", "{}"); !errors.Is(err, ErrCredentialUpdateIncomplete) {
			t.Fatalf("%+v: err %v", other, err)
		}
		if projectionOf(t, home) != before {
			t.Fatalf("%+v changed the home", other)
		}
	}
	if err := updateWith(home, installA, "team-cert.pem", "whole\n"); err != nil {
		t.Fatal(err)
	}
	assertState(t, home, 1, false)
}

// While a reader serves the home, a change made without publishing is never
// blessed by a later update.
func TestAnUnpublishedChangeIsRefusedByEverySupportedWriter(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	reader, err := LockCredentialReader(home)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := updateWith(home, installA, "team-cert.pem", "published\n"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, home, "team-cert.pem", "changed elsewhere\n")
	before := projectionOf(t, home)
	if err := updateWith(home, importA, "id-chain.json", "{}"); !errors.Is(err, ErrCredentialUpdateUnpublished) {
		t.Fatalf("err %v", err)
	}
	if projectionOf(t, home) != before {
		t.Fatal("the refused update changed the home")
	}
	assertState(t, home, 1, false)
}

// A writer that died after publishing but before removing its marker
// committed; the next writer clears the marker and proceeds.
func TestAMarkerLeftAfterPublishingIsCommitted(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	if err := updateWith(home, installA, "team-cert.pem", "published\n"); err != nil {
		t.Fatal(err)
	}
	state, _ := ReadCredentialState(home)
	leftover, _ := json.Marshal(CredentialMarker{TxID: "dead", Operation: installA,
		Base: CredentialBase{Generation: 0}, TargetGeneration: state.Generation})
	writeFile(t, home, credentialMarkerFile, string(leftover))
	if state, _ := ReadCredentialState(home); !state.Committed() {
		t.Fatal("a marker left after publishing is not recognized as committed")
	}
	if err := updateWith(home, importA, "id-chain.json", "{}"); err != nil {
		t.Fatal(err)
	}
	assertState(t, home, 2, false)
}

// A restart adopts a home an unsupported writer changed, once validated; it
// never adopts an interrupted update.
func TestARestartAdoptsAValidatedHomeButNeverAnInterruptedUpdate(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	if err := updateWith(home, installA, "team-cert.pem", "published\n"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, home, "team-cert.pem", "changed by an older writer\n")
	serving, err := LockCredentialReader(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateWith(home, importA, "id-chain.json", "{}"); !errors.Is(err, ErrCredentialUpdateUnpublished) {
		t.Fatalf("err %v", err)
	}
	_ = serving.Close() // the serving reader stops; the restart adopts
	refused := errors.New("not valid")
	if adopted, err := AdoptCredentials(home, func(*CredentialCapture) error { return refused }); adopted || !errors.Is(err, refused) {
		t.Fatalf("an invalid home was adopted: %v %v", adopted, err)
	}
	if adopted, err := AdoptCredentials(home, func(*CredentialCapture) error { return nil }); !adopted || err != nil {
		t.Fatalf("adopted %v err %v", adopted, err)
	}
	assertState(t, home, 2, false)
	if err := updateWith(home, importA, "id-chain.json", "{}"); err != nil {
		t.Fatalf("a supported writer after the restart: %v", err)
	}
	failed := errors.New("half written")
	_ = UpdateCredentials(home, installB, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		return failed
	})
	if adopted, err := AdoptCredentials(home, func(*CredentialCapture) error { return nil }); adopted || !errors.Is(err, ErrCredentialUpdateIncomplete) {
		t.Fatalf("an interrupted update was adopted: %v %v", adopted, err)
	}
}

// The first update of a home that never published, interrupted, is recovered
// by the same operation from the absent manifest it recorded as its base.
func TestAnInterruptedFirstUpdateIsRecoverable(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	_ = UpdateCredentials(home, installA, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		return errors.New("crashed")
	})
	assertState(t, home, 0, true)
	if err := updateWith(home, installA, "team-cert.pem", "whole\n"); err != nil {
		t.Fatal(err)
	}
	assertState(t, home, 1, false)
}

// A home that changes while an update waits (for example for the released
// install lock an older aw holds) is rechecked before the first write.
func TestAnUpdateRechecksItsBaseBeforeItsFirstWrite(t *testing.T) {
	for name, published := range map[string]bool{"a published home": true, "a home that never published": false} {
		home := credentialHome(t, "team-cert.pem")
		if published {
			if err := updateWith(home, installA, "team-cert.pem", "published\n"); err != nil {
				t.Fatal(err)
			}
		}
		before := projectionOf(t, home)
		err := UpdateCredentials(home, importA, func(begin func() error) error {
			writeFile(t, home, "team-cert.pem", "written by an older aw meanwhile\n")
			if err := begin(); err != nil {
				return err
			}
			t.Errorf("%s: the update wrote over a changed home", name)
			return nil
		})
		if !errors.Is(err, ErrCredentialUpdateUnpublished) {
			t.Errorf("%s: err %v", name, err)
		}
		if state, _ := ReadCredentialState(home); state.Marker != nil || projectionOf(t, home) == before {
			t.Errorf("%s: state %+v", name, state)
		}
	}
}

// With no reader serving the home there is nothing to keep coherent: a
// supported update publishes over a change made without a generation, but
// never over another operation's interrupted update.
func TestWithNoReaderASupportedUpdatePublishesOverAnUnpublishedChange(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	if err := updateWith(home, installA, "team-cert.pem", "published\n"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, home, "team-cert.pem", "changed by an older aw\n")
	if err := updateWith(home, importA, "id-chain.json", "{}"); err != nil {
		t.Fatalf("err %v", err)
	}
	assertState(t, home, 2, false)
	_, other, _ := awid.GenerateKeypair()
	_ = os.Remove(filepath.Join(home, "signing.key"))
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), other); err != nil {
		t.Fatal(err)
	}
	if err := updateWith(home, importA, "id-chain.json", "[]"); !errors.Is(err, ErrCredentialUpdateUnpublished) {
		t.Fatalf("a home whose identity no longer names its key was adopted: %v", err)
	}
	if err := os.Remove(filepath.Join(home, "signing.key")); err != nil {
		t.Fatal(err)
	}
	_ = UpdateCredentials(home, installB, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		return errors.New("interrupted")
	})
	if err := updateWith(home, importA, "id-chain.json", "[]"); !errors.Is(err, ErrCredentialUpdateIncomplete) {
		t.Fatalf("another operation's interrupted update: err %v", err)
	}
}

// A writer with no reader holds the reader lock for its whole update, so a
// reader cannot start while it writes.
func TestAWriterWithNoReaderHoldsTheReaderLockWhileItWrites(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	err := UpdateCredentials(home, installA, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		if lock, err := LockCredentialReader(home); !errors.Is(err, ErrLockUnavailable) {
			_ = lock.Close()
			t.Fatalf("a reader started while the update wrote: %v", err)
		}
		writeFile(t, home, "team-cert.pem", "written\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := LockCredentialReader(home)
	if err != nil {
		t.Fatalf("no reader after the update: %v", err)
	}
	_ = reader.Close()
}

// An interrupted update whose writes all landed is published by its retry,
// even though the retry has nothing left to write.
func TestARetryOfAnUpdateThatWroteEverythingPublishesIt(t *testing.T) {
	home := credentialHome(t, "team-cert.pem")
	_ = UpdateCredentials(home, installA, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeFile(t, home, "team-cert.pem", "whole\n")
		return errors.New("died before publishing")
	})
	if err := UpdateCredentials(home, installA, func(func() error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertState(t, home, 1, false)
}
