package awconfig

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSharedHoldersCoexistAndExcludeAnExclusiveHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "home.lock")
	first, err := TryLockShared(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := TryLockShared(path)
	if err != nil {
		t.Fatalf("a second shared holder: %v", err)
	}
	if _, err := TryLockExclusive(path); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("an exclusive lock was taken while shared holders held it: %v", err)
	}
	_ = first.Close()
	_ = second.Close()
	exclusive, err := TryLockExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLockShared(path); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("a shared lock was taken while an exclusive holder held it: %v", err)
	}
	_ = exclusive.Close()
}
