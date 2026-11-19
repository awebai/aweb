package awconfig

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

type countedInvitationFiles struct {
	fs.FS
	reads int
}

func (files *countedInvitationFiles) ReadFile(name string) ([]byte, error) {
	files.reads++
	return fs.ReadFile(files.FS, name)
}

func TestInvitationRequestLookupReadsAreIndependentOfHistory(t *testing.T) {
	for _, history := range []int{1, 200} {
		t.Run(fmt.Sprint(history), func(t *testing.T) {
			store := IDInvitationFileStore{Dir: filepath.Join(t.TempDir(), "invitations")}
			for i := 0; i < history; i++ {
				inv := testInvitation(fmt.Sprintf("%08x-0000-4000-8000-000000000001", i+1))
				if err := store.PutInvitation(inv); err != nil {
					t.Fatal(err)
				}
			}
			wanted := testInvitation("ffffffff-0000-4000-8000-000000000001")
			wanted.Request = &awid.IDRequestRecord{RequestID: "target", State: awid.IDRequestPending}
			if err := store.PutInvitation(wanted); err != nil {
				t.Fatal(err)
			}
			files := &countedInvitationFiles{FS: os.DirFS(store.Dir)}
			found, err := (invitationRequestIndex{store: store, files: files}).lookup("target")
			if err != nil || found == nil || found.InvitationID != wanted.InvitationID {
				t.Fatalf("found=%v err=%v", found, err)
			}
			if files.reads > 3 {
				t.Fatalf("history=%d caused %d file reads", history, files.reads)
			}
			files.reads = 0
			missing, err := (invitationRequestIndex{store: store, files: files}).lookup("new request")
			if err != nil || missing != nil || files.reads > 2 {
				t.Fatalf("absent=%v err=%v reads=%d", missing, err, files.reads)
			}
		})
	}
}

func TestInvitationRequestIndexRebuildsAfterReleasedWriter(t *testing.T) {
	store := IDInvitationFileStore{Dir: filepath.Join(t.TempDir(), "invitations")}
	first := testInvitation("10000000-0000-4000-8000-000000000001")
	first.Request = &awid.IDRequestRecord{RequestID: "first"}
	if err := store.PutInvitation(first); err != nil {
		t.Fatal(err)
	}
	second := testInvitation("20000000-0000-4000-8000-000000000002")
	second.Request = &awid.IDRequestRecord{RequestID: "released"}
	data, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	// This is the released writer's atomic replacement, without index updates.
	if err := atomicWriteFile(filepath.Join(store.Dir, second.InvitationID+".json"), data); err != nil {
		t.Fatal(err)
	}
	found, err := store.InvitationForRequest("released")
	if err != nil || found == nil || found.InvitationID != second.InvitationID {
		t.Fatalf("released record=%v err=%v", found, err)
	}
	first.Request.RequestID = "changed"
	if err := store.PutInvitation(first); err != nil {
		t.Fatal(err)
	}
	if found, err := store.InvitationForRequest("first"); err != nil || found != nil {
		t.Fatalf("obsolete lookup=%v err=%v", found, err)
	}
	if found, err := store.InvitationForRequest("changed"); err != nil || found == nil {
		t.Fatalf("changed lookup=%v err=%v", found, err)
	}
}

func TestInvitationRequestIndexRefusesCorruptionAndDuplicateBindings(t *testing.T) {
	store := IDInvitationFileStore{Dir: filepath.Join(t.TempDir(), "invitations")}
	first := testInvitation("10000000-0000-4000-8000-000000000001")
	first.Request = &awid.IDRequestRecord{RequestID: "same"}
	if err := store.PutInvitation(first); err != nil {
		t.Fatal(err)
	}
	second := testInvitation("20000000-0000-4000-8000-000000000002")
	second.Request = &awid.IDRequestRecord{RequestID: "same"}
	if err := store.PutInvitation(second); err == nil {
		t.Fatal("second invitation accepted the same request")
	}
	indexPath := filepath.Join(store.Dir, requestFileIndexDir, requestFileIndexBindingName("same"))
	if err := os.WriteFile(indexPath, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InvitationForRequest("same"); err == nil {
		t.Fatal("corrupt binding was absence")
	}
}

func TestInvitationRequestIndexRecoversIncompleteBuildAndKeepsBindingsPrivate(t *testing.T) {
	store := IDInvitationFileStore{Dir: filepath.Join(t.TempDir(), "invitations")}
	inv := testInvitation("10000000-0000-4000-8000-000000000001")
	inv.Request = &awid.IDRequestRecord{RequestID: "request"}
	if err := store.PutInvitation(inv); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(store.Dir, requestFileIndexDir)
	// An interrupted rebuild has no completeness marker. A lookup must rebuild
	// from the authoritative record rather than treat its missing binding as absent.
	if err := os.Remove(filepath.Join(directory, requestFileIndexGenerationFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, requestFileIndexBindingName("request"))); err != nil {
		t.Fatal(err)
	}
	if found, err := store.InvitationForRequest("request"); err != nil || found == nil {
		t.Fatalf("partial index was absence: %v %v", found, err)
	}
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		expected := fs.FileMode(0600)
		if entry.IsDir() {
			expected = 0700
		}
		if info.Mode().Perm() != expected {
			return fmt.Errorf("index mode %s: %o", path, info.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInvitationRequestIndexRefusesSymlinkDirectory(t *testing.T) {
	store := IDInvitationFileStore{Dir: filepath.Join(t.TempDir(), "invitations")}
	inv := testInvitation("10000000-0000-4000-8000-000000000001")
	if err := store.PutInvitation(inv); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(store.Dir, requestFileIndexDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InvitationForRequest("request"); err == nil {
		t.Fatal("followed a symlink index directory")
	}
}
