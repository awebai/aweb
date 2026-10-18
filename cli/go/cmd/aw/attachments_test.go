package main

import (
	"github.com/awebai/aw/awid"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAttachmentFileIsExplicitExclusiveAndRefusesSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "download")
	if err := writeAttachmentFile(target, []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	if err := writeAttachmentFile(target, []byte("replace")); err == nil {
		t.Fatal("existing file overwritten")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "bytes" {
		t.Fatal("original download changed")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAttachmentFile(link, []byte("replace")); err == nil {
		t.Fatal("symlink followed")
	}
}

func TestAttachmentFilenameEscapedInMailShow(t *testing.T) {
	out := formatMailShowResponse(&awid.InboxResponse{Messages: []awid.InboxMessage{{MessageID: "m", FromAlias: "sender", Attachments: []awid.AttachmentDescriptor{{ID: "id", Filename: "bad\x1b[2J\u202ename", Size: 1}}}}}, "")
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\u202e") || !strings.Contains(out, `\x1b`) || !strings.Contains(out, `\u202e`) {
		t.Fatal("attachment name drove terminal output")
	}
}
