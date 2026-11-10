package awid

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// A key is put in place with a hard link. A filesystem without hard links
// answers the link with one of these errors, and the operator is told what
// that means and what to do, not shown the raw link error alone.
func TestExclusiveKeyWriteErrorExplainsAFilesystemWithoutHardLinks(t *testing.T) {
	path := "/mnt/share/identity/signing.key"
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.EXDEV} {
		link := &os.LinkError{Op: "link", Old: path + ".tmp.1", New: path, Err: errno}
		err := exclusiveKeyWriteError(path, fmt.Errorf("atomic write %s: %w", path, link))
		want := "the filesystem holding " + path + " does not support hard links; keep the identity home on a local filesystem"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v: error does not explain the missing hard links: %v", errno, err)
		}
		if !errors.Is(err, errno) {
			t.Errorf("%v: the link error is not kept as the cause: %v", errno, err)
		}
	}
}

func TestExclusiveKeyWriteErrorKeepsOtherFailuresAsTheyAre(t *testing.T) {
	path := "/home/agent/.aw/signing.key"
	others := []error{
		&os.LinkError{Op: "link", Old: path + ".tmp.1", New: path, Err: syscall.EEXIST},
		&os.LinkError{Op: "link", Old: path + ".tmp.1", New: path, Err: syscall.EACCES},
		// The same errors from a step that is not the link say nothing about hard links.
		&os.PathError{Op: "open", Path: path + ".tmp.1", Err: syscall.EPERM},
		&os.PathError{Op: "chmod", Path: path + ".tmp.1", Err: syscall.ENOTSUP},
	}
	for _, cause := range others {
		err := exclusiveKeyWriteError(path, fmt.Errorf("atomic write %s: %w", path, cause))
		if strings.Contains(err.Error(), "hard links") {
			t.Errorf("%v: reported as a filesystem without hard links: %v", cause, err)
		}
		if !errors.Is(err, cause) {
			t.Errorf("%v: the cause is not kept: %v", cause, err)
		}
		if !strings.Contains(err.Error(), "create private key "+path+" without overwrite") {
			t.Errorf("%v: error does not say what was being done: %v", cause, err)
		}
	}
	if !errors.Is(exclusiveKeyWriteError(path, fmt.Errorf("atomic write %s: %w", path, others[0])), os.ErrExist) {
		t.Error("an occupied destination no longer matches os.ErrExist")
	}
}
