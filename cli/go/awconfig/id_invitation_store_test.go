package awconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/awebai/aw/awid"
)

func testInvitation(id string) *awid.IDInvitation {
	return &awid.IDInvitation{
		InvitationID: id,
		Mode:         awid.IDInvitationSelfCustodial,
		Parent:       map[string]any{"kind": "namespace", "id": "example.com"},
		Domain:       "example.com",
		Kind:         "human",
		Recipient:    "Bob, met at the offsite",
		ExpiresAt:    "2026-11-04T00:00:00Z",
	}
}

func TestIDInvitationFileStoreRoundTrip(t *testing.T) {
	store := IDInvitationFileStore{Dir: filepath.Join(t.TempDir(), "invitations")}
	if got, err := store.Invitation("10000000-0000-4000-8000-000000000001"); err != nil || got != nil {
		t.Fatalf("missing invitation: %v %v", got, err)
	}
	if all, err := store.Invitations(); err != nil || len(all) != 0 {
		t.Fatalf("empty store lists %v (%v)", all, err)
	}
	second, first := testInvitation("20000000-0000-4000-8000-000000000002"), testInvitation("10000000-0000-4000-8000-000000000001")
	for _, inv := range []*awid.IDInvitation{second, first} {
		if err := store.PutInvitation(inv); err != nil {
			t.Fatal(err)
		}
	}
	first.Request = &awid.IDRequestRecord{RequestID: "30000000-0000-4000-8000-000000000003", Request: "{}", State: awid.IDRequestPending}
	if err := store.PutInvitation(first); err != nil {
		t.Fatal(err)
	}
	got, err := store.Invitation(first.InvitationID)
	if err != nil || !reflect.DeepEqual(got, first) {
		t.Fatalf("got %+v (%v) want %+v", got, err, first)
	}
	all, err := store.Invitations()
	if err != nil || len(all) != 2 || all[0].InvitationID != first.InvitationID || all[1].InvitationID != second.InvitationID {
		t.Fatalf("listed %+v (%v)", all, err)
	}
}

func TestIDInvitationFileStoreKeepsInvitationsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dir := filepath.Join(t.TempDir(), "invitations")
	store := IDInvitationFileStore{Dir: dir}
	if err := store.PutInvitation(testInvitation("10000000-0000-4000-8000-000000000001")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v (%v)", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries %v (%v)", entries, err)
	}
	file, err := os.Stat(filepath.Join(dir, entries[0].Name()))
	if err != nil || file.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v (%v)", file, err)
	}
}

func TestIDInvitationFileStoreRefusesAnInvalidOrMismatchedID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "invitations")
	store := IDInvitationFileStore{Dir: dir}
	for _, id := range []string{"../escape", "", "not-a-uuid"} {
		if err := store.PutInvitation(testInvitation(id)); err == nil {
			t.Fatalf("stored invitation %q", id)
		}
	}
	if err := store.PutInvitation(testInvitation("10000000-0000-4000-8000-000000000001")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "10000000-0000-4000-8000-000000000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "20000000-0000-4000-8000-000000000002.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Invitation("20000000-0000-4000-8000-000000000002"); err == nil {
		t.Fatal("loaded an invitation filed under another ID")
	}
}
