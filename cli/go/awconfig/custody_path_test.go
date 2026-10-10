package awconfig

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCustodyDefaultSocketLongRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), strings.Repeat("resident", 25), ".aw")
	socket := CustodySocketPath(root)
	if len(socket) > 103 {
		t.Fatalf("long root yields %d-byte socket: %s", len(socket), socket)
	}
	if socket != CustodySocketPath(filepath.Join(root, ".")) {
		t.Fatal("path is not stable")
	}
	if socket == CustodySocketPath(root+"other") {
		t.Fatal("distinct roots share socket")
	}
	short := filepath.Join(string(filepath.Separator), "short", ".aw")
	if got := CustodySocketPath(short); got != filepath.Join(short, "run", "custody.sock") {
		t.Fatalf("short path changed: %s", got)
	}
}
