//go:build !windows

package custodypath

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckProtectsDefaultAndConfiguredSocketLocations(t *testing.T) {
	for _, location := range []string{"default", "configured"} {
		for _, scenario := range []string{"private", "shared-directory", "shared-socket", "symlink-socket", "regular-file"} {
			t.Run(location+"/"+scenario, func(t *testing.T) {
				root := shortCanonicalDir(t)
				socket := Default(root)
				if location == "configured" {
					socket = filepath.Join(root, "custom", "c.sock")
				}
				if IsRuntime(socket) {
					t.Fatal("test must exercise the non-runtime socket branch")
				}
				dir := filepath.Dir(socket)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "regular-file":
					if err := os.WriteFile(socket, []byte("not a socket"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink-socket":
					if err := os.Symlink(filepath.Join(root, "elsewhere"), socket); err != nil {
						t.Fatal(err)
					}
				default:
					listener, err := net.Listen("unix", socket)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := listener.Close(); err != nil {
							t.Error(err)
						}
					})
					if err := os.Chmod(socket, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "shared-directory" {
					if err := os.Chmod(dir, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "shared-socket" {
					if err := os.Chmod(socket, 0666); err != nil {
						t.Fatal(err)
					}
				}
				err := Check(socket)
				if (err == nil) != (scenario == "private") {
					t.Fatalf("Check(%s): %v", socket, err)
				}
			})
		}
	}
}
