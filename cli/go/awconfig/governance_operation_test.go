package awconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const testOperationID = "11111111-1111-4111-8111-111111111111"

func pendingOperation() *PendingGovernanceOperation {
	return &PendingGovernanceOperation{
		OperationID:   testOperationID,
		RequestOrigin: "https://secrets.example.com",
		HumanOrigin:   "https://console.secrets.example.com",
		// Bytes no encoder would write: only an exact copy matches.
		Body: []byte(` {"operation_id":"11111111-1111-4111-8111-111111111111", "z":1,"a":"é"}`),
	}
}

func TestAPendingGovernanceOperationKeepsItsExactBodyAndOrigins(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := pendingOperation()
	if err := SavePendingGovernanceOperation(want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPendingGovernanceOperation(testOperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !bytes.Equal(got.Body, want.Body) || got.RequestOrigin != want.RequestOrigin || got.HumanOrigin != want.HumanOrigin || got.OperationID != want.OperationID {
		t.Fatalf("loaded %+v", got)
	}
}

func TestAPendingGovernanceOperationIsReadableOnlyByItsOwner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := SavePendingGovernanceOperation(pendingOperation()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".config", "aw", "governance")
	for path, mode := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, testOperationID+".json"): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s has mode %v, want %v", path, info.Mode().Perm(), mode)
		}
	}
}

func TestARemovedOrUnknownOperationIsNotPending(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := SavePendingGovernanceOperation(pendingOperation()); err != nil {
		t.Fatal(err)
	}
	if err := RemovePendingGovernanceOperation(testOperationID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{testOperationID, "22222222-2222-4222-8222-222222222222"} {
		got, err := LoadPendingGovernanceOperation(id)
		if err != nil || got != nil {
			t.Errorf("%s: %+v, %v", id, got, err)
		}
	}
	if err := RemovePendingGovernanceOperation(testOperationID); err != nil {
		t.Fatalf("removing an absent operation: %v", err)
	}
}

func TestAnOperationIDThatIsNotAUUIDNamesNoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, id := range []string{"", "../escape", "11111111-1111-4111-8111-111111111111/x", "not-a-uuid", "11111111-1111-4111-8111-11111111111G"} {
		op := pendingOperation()
		op.OperationID = id
		if err := SavePendingGovernanceOperation(op); err == nil {
			t.Errorf("saved %q", id)
		}
		if _, err := LoadPendingGovernanceOperation(id); err == nil {
			t.Errorf("loaded %q", id)
		}
		if err := RemovePendingGovernanceOperation(id); err == nil {
			t.Errorf("removed %q", id)
		}
	}
}

func TestASavedOperationNamesTheIDItIsStoredUnder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := SavePendingGovernanceOperation(pendingOperation()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".config", "aw", "governance")
	other := "33333333-3333-4333-8333-333333333333"
	if err := os.Rename(filepath.Join(dir, testOperationID+".json"), filepath.Join(dir, other+".json")); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadPendingGovernanceOperation(other); err == nil {
		t.Fatalf("a file for another operation loaded as %s: %+v", other, got)
	}
}

func TestAQuarantinedOperationKeepsItsEvidenceWithItsExactBody(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	op := pendingOperation()
	op.Quarantine = &GovernanceQuarantine{State: "committed", Code: "", Signing: []byte("signed bytes\x00"),
		Signature: bytes.Repeat([]byte{7}, 64), Verification: "signature_verified", ObservedAt: "2026-11-13T12:00:00Z"}
	if err := SavePendingGovernanceOperation(op); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPendingGovernanceOperation(testOperationID)
	if err != nil {
		t.Fatal(err)
	}
	q := got.Quarantine
	if q == nil || q.State != "committed" || !bytes.Equal(q.Signing, op.Quarantine.Signing) || !bytes.Equal(q.Signature, op.Quarantine.Signature) ||
		q.Verification != "signature_verified" || q.ObservedAt != "2026-11-13T12:00:00Z" || !bytes.Equal(got.Body, op.Body) {
		t.Fatalf("loaded %+v", got)
	}
	unmarked := pendingOperation()
	unmarked.OperationID = "22222222-2222-4222-8222-222222222222"
	if err := SavePendingGovernanceOperation(unmarked); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadPendingGovernanceOperation(unmarked.OperationID); got.Quarantine != nil {
		t.Fatal("an ordinary pending operation reads as quarantined")
	}
}
