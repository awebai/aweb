package awconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/awebai/aw/awid"
)

const testCertificateID = "sha256:101a89303275362d5d3a366a19a59911e1dda6d39b57b45bbb2bd0e43e1cb2d9"

func testIssuanceEntry() *awid.IDIssuanceEntry {
	return &awid.IDIssuanceEntry{
		CertificateID: testCertificateID,
		Signed: map[string]any{
			"certificate": map[string]any{"v": json.Number("1"), "id": "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x"},
			"signature":   "sig",
		},
		RecordedAt: "2026-10-26T00:04:00Z",
		Resign:     &awid.IDResignRecord{RequestID: "20000000-0000-4000-8000-000000000004", Request: "{}", State: awid.IDResignPending},
	}
}

func TestIDIssuanceFileStoreRoundTrip(t *testing.T) {
	store := IDIssuanceFileStore{Dir: filepath.Join(t.TempDir(), "id-issuance")}
	if got, err := store.Entry(testCertificateID); err != nil || got != nil {
		t.Fatalf("missing entry: %v %v", got, err)
	}
	want := testIssuanceEntry()
	if err := store.Put(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Entry(testCertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	byRequest, err := store.EntryForRequest("20000000-0000-4000-8000-000000000004")
	if err != nil || !reflect.DeepEqual(byRequest, want) {
		t.Fatalf("by request: %+v %v", byRequest, err)
	}
	if none, err := store.EntryForRequest("20000000-0000-4000-8000-000000000009"); err != nil || none != nil {
		t.Fatalf("unknown request: %+v %v", none, err)
	}
}

func TestIDIssuanceFileStoreWritesPrivateFilesAndNoTemporaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dir := filepath.Join(t.TempDir(), "id-issuance")
	store := IDIssuanceFileStore{Dir: dir}
	if err := store.Put(testIssuanceEntry()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d files, want only the entry", len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("entry mode %v", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", dirInfo.Mode().Perm())
	}
}

func TestIDIssuanceFileStoreRefusesNonCertificateNames(t *testing.T) {
	store := IDIssuanceFileStore{Dir: t.TempDir()}
	for _, id := range []string{"sha256:../../etc/passwd", "sha256:ABCDEF", "101a89303275362d5d3a366a19a59911e1dda6d39b57b45bbb2bd0e43e1cb2d9", "sha256:101a89303275362d5d3a366a19a59911e1dda6d39b57b45bbb2bd0e43e1cb2d"} {
		if _, err := store.Entry(id); err == nil {
			t.Fatalf("Entry accepted %q", id)
		}
		entry := testIssuanceEntry()
		entry.CertificateID = id
		if err := store.Put(entry); err == nil {
			t.Fatalf("Put accepted %q", id)
		}
	}
}

func TestIDIssuanceFileStoreRefusesAnEntryFiledUnderAnotherName(t *testing.T) {
	dir := t.TempDir()
	store := IDIssuanceFileStore{Dir: dir}
	if err := store.Put(testIssuanceEntry()); err != nil {
		t.Fatal(err)
	}
	other := "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
	src := filepath.Join(dir, "101a89303275362d5d3a366a19a59911e1dda6d39b57b45bbb2bd0e43e1cb2d9.json")
	if err := os.Rename(src, filepath.Join(dir, "0000000000000000000000000000000000000000000000000000000000000000.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Entry(other); err == nil {
		t.Fatal("an entry filed under another certificate's name was returned")
	}
}
