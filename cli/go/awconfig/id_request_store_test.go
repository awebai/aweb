package awconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestIDRequestFileStoreRoundTripsAndStaysPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "requests")
	store := IDRequestFileStore{Dir: dir}
	const id = "20000000-0000-4000-8000-000000000001"
	if got, err := store.Request(id); err != nil || got != nil {
		t.Fatalf("missing request: %v %v", got, err)
	}
	want := &IDOutgoingRequest{RequestID: id, InvitationID: "10000000-0000-4000-8000-000000000001", Request: "{}", State: IDRequestOutstanding}
	if err := store.Put(want); err != nil {
		t.Fatal(err)
	}
	want.State, want.Response, want.Registration = IDRequestImported, "{\"v\":1}", "pending"
	if err := store.Put(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Request(id)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v (%v) want %+v", got, err, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v (%v)", info, err)
		}
		file, err := os.Stat(filepath.Join(dir, id+".json"))
		if err != nil || file.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %v (%v)", file, err)
		}
	}
	for _, bad := range []string{"../escape", "", "not-a-uuid"} {
		if err := store.Put(&IDOutgoingRequest{RequestID: bad}); err == nil {
			t.Fatalf("stored request %q", bad)
		}
	}
}
