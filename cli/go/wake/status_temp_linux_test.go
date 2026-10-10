//go:build linux

package wake

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Observe actual kernel CREATE notifications, without replacing filesystem
// calls. Periodic status writes must not introduce an unbounded set of names.
func TestStatusWritesReuseTemporaryName(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if _, err = syscall.InotifyAddWatch(fd, store.Dir(), syscall.IN_CREATE); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for i := 0; i < 32; i++ {
		if err = store.SaveStatus(Status{StateDir: store.Dir(), UpdatedAt: time.Unix(int64(i+1), 0)}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8192)
		for {
			n, e := syscall.Read(fd, buf)
			if e == syscall.EAGAIN {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			for off := 0; off+16 <= n; {
				size := int(binary.NativeEndian.Uint32(buf[off+12 : off+16]))
				end := off + 16 + size
				if end > n {
					t.Fatal("truncated inotify event")
				}
				name := strings.TrimRight(string(buf[off+16:end]), "\x00")
				if strings.HasPrefix(name, ".tmp-") {
					names[name] = true
				}
				off = end
			}
		}
		got, ok, e := store.LoadStatus()
		if e != nil || !ok || !got.UpdatedAt.Equal(time.Unix(int64(i+1), 0)) {
			t.Fatalf("snapshot failed to advance: found=%v err=%v", ok, e)
		}
	}
	if len(names) != 1 {
		t.Fatalf("status writes created %d distinct temporary names; want one reusable writer name", len(names))
	}
	matches, err := filepath.Glob(filepath.Join(store.Dir(), ".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary artifacts remain: %d", len(matches))
	}
}
