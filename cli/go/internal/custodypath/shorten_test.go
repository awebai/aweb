package custodypath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShortenSocketCanonicalAndDistinct(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, strings.Repeat("p", 120))
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, strings.Repeat("a", 120))
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	socket := Shorten(filepath.Join(parent, "control.sock"), 100)
	if len(socket) > 100 || !IsRuntime(socket) {
		t.Fatalf("not a short private locator: %s", socket)
	}
	if socket != Shorten(filepath.Join(alias, "control.sock"), 100) {
		t.Fatal("aliases locate different sockets")
	}
	if socket == Shorten(filepath.Join(parent, "other.sock"), 100) || socket == Default(parent) {
		t.Fatal("socket namespaces collide")
	}
	short := "/private/tmp/aw-short/control.sock"
	if Shorten(short, 100) != short {
		t.Fatal("short override changed")
	}
}
