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
		Resign:     &awid.IDRequestRecord{RequestID: "20000000-0000-4000-8000-000000000004", Request: "{}", State: awid.IDRequestPending},
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
	bySubject, err := store.EntryForSubject("did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x")
	if err != nil || !reflect.DeepEqual(bySubject, want) {
		t.Fatalf("by subject: %+v %v", bySubject, err)
	}
	if none, err := store.EntryForSubject("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"); err != nil || none != nil {
		t.Fatalf("unknown subject: %+v %v", none, err)
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
	store := IDIssuanceFileStore{Dir: filepath.Join(t.TempDir(), "id-issuance")}
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
	dir := filepath.Join(t.TempDir(), "id-issuance")
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

func TestIDIssuanceFileStoreRefusesALooseDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dir := filepath.Join(t.TempDir(), "id-issuance")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := IDIssuanceFileStore{Dir: dir}
	if err := store.Put(testIssuanceEntry()); err == nil {
		t.Fatal("wrote into a directory other users can read")
	}
	if _, err := store.Entry(testCertificateID); err == nil {
		t.Fatal("read from a directory other users can read")
	}
	if _, err := store.EntryForRequest("20000000-0000-4000-8000-000000000004"); err == nil {
		t.Fatal("scanned a directory other users can read")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("directory holds %d files", len(entries))
	}
}

func TestIDIssuanceFileStoreRefusesASymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlinks")
	}
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "id-issuance")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if err := (IDIssuanceFileStore{Dir: dir}).Put(testIssuanceEntry()); err == nil {
		t.Fatal("wrote through a symlinked directory")
	}
}

func TestIDIssuanceFileStoreRefusesAFileInPlaceOfItsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id-issuance")
	if err := os.WriteFile(dir, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (IDIssuanceFileStore{Dir: dir}).Entry(testCertificateID); err == nil {
		t.Fatal("read entries from a file standing in for the directory")
	}
}
