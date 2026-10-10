package wake

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStatusTemporaryCollisionPreservesSnapshot(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err = s.SaveStatus(Status{UpdatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			previous, err := os.ReadFile(s.StatusPath())
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(s.Dir(), "untouched")
			want := []byte("do not overwrite")
			if kind == "symlink" {
				if err = os.WriteFile(target, want, 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, s.statusTemp)
			} else {
				target = s.statusTemp
				err = os.WriteFile(target, want, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.SaveStatus(Status{UpdatedAt: time.Unix(2, 0)}); !os.IsExist(err) {
				t.Fatalf("collision was not refused: %v", err)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("collision target changed: %v", err)
			}
			got, err = os.ReadFile(s.StatusPath())
			if err != nil || !bytes.Equal(got, previous) {
				t.Fatalf("previous snapshot changed: %v", err)
			}
			if err = os.Remove(s.statusTemp); err != nil {
				t.Fatal(err)
			}
			if err = s.SaveStatus(Status{UpdatedAt: time.Unix(3, 0)}); err != nil {
				t.Fatal(err)
			}
			gotStatus, ok, err := s.LoadStatus()
			if err != nil || !ok || !gotStatus.UpdatedAt.Equal(time.Unix(3, 0)) {
				t.Fatalf("recovery did not advance snapshot: %v", err)
			}
		})
	}
}

func TestStatusAtomicReadersAndIndependentWriters(t *testing.T) {
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.SaveStatus(Status{UpdatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	readDone := make(chan struct{})
	errs := make(chan error, 4)
	go func() {
		defer close(readDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			raw, e := os.ReadFile(a.StatusPath())
			if e != nil {
				errs <- e
				return
			}
			var status Status
			if e = json.Unmarshal(raw, &status); e != nil {
				errs <- e
				return
			}
		}
	}()
	var wg sync.WaitGroup
	for _, s := range []*Store{a, a, b} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			for i := 0; i < 32; i++ {
				if e := s.SaveStatus(Status{UpdatedAt: time.Unix(int64(i+2), 0)}); e != nil {
					errs <- e
					return
				}
			}
		}(s)
	}
	wg.Wait()
	close(stop)
	<-readDone
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if a.statusTemp == b.statusTemp {
		t.Error("independent writers share a temporary name")
	}
	info, err := os.Stat(a.StatusPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("status mode: %o", info.Mode().Perm())
	}
	for _, s := range []*Store{a, b} {
		if _, err = os.Lstat(s.statusTemp); !os.IsNotExist(err) {
			t.Errorf("scratch file remains: %v", err)
		}
	}
}
