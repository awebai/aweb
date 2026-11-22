package awconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestIDIssuanceRequestLookupDoesNotReadUnrelatedHistory(t *testing.T) {
	store := IDIssuanceFileStore{Dir: filepath.Join(t.TempDir(), "id-issuance")}
	unrelated := testIssuanceEntry()
	unrelated.Resign = nil
	if err := store.Put(unrelated); err != nil {
		t.Fatal(err)
	}
	target := testIssuanceEntry()
	target.CertificateID = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := store.Put(target); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EntryForRequest("never received"); err != nil {
		t.Fatal(err)
	}
	path, err := store.path(unrelated.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	// A byte-level corruption of an unrelated old record must not turn an indexed
	// request lookup into a history read. Listing that history still diagnoses it.
	if err := os.WriteFile(path, []byte("corrupt unrelated record"), 0600); err != nil {
		t.Fatal(err)
	}
	found, err := store.EntryForRequest(target.Resign.RequestID)
	if err != nil || found == nil || found.CertificateID != target.CertificateID {
		t.Fatalf("looked through unrelated history: %v %v", found, err)
	}
}

func TestIDIssuanceRequestLookupReadsAreIndependentOfHistory(t *testing.T) {
	for _, history := range []int{1, 200} {
		t.Run(fmt.Sprint(history), func(t *testing.T) {
			store := IDIssuanceFileStore{Dir: filepath.Join(t.TempDir(), "id-issuance")}
			for i := 0; i < history; i++ {
				entry := testIssuanceEntry()
				entry.CertificateID = fmt.Sprintf("sha256:%064x", i+1)
				entry.Resign = nil
				if err := store.Put(entry); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.EntryForRequest("not received"); err != nil {
				t.Fatal(err)
			}
			files := &countedInvitationFiles{FS: os.DirFS(store.Dir)}
			index := issuanceRequestIndex{store: store, files: files}
			if found, err := index.lookup("not received"); err != nil || found != nil || files.reads > 2 {
				t.Fatalf("history=%d reads=%d found=%v err=%v", history, files.reads, found, err)
			}
			// A released writer does not know the index; its atomic replacement must
			// invalidate it and make the newly received re-sign visible.
			entry := testIssuanceEntry()
			path, err := store.path(entry.CertificateID)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := atomicWriteFile(path, data); err != nil {
				t.Fatal(err)
			}
			if found, err := store.EntryForRequest(entry.Resign.RequestID); err != nil || found == nil {
				t.Fatalf("released write hidden: %v %v", found, err)
			}
		})
	}
}
