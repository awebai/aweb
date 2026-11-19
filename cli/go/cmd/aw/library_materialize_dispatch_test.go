package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLibraryManifestLocalMaterializeRejectsUnsignedReadOnlyToolBeforeRequest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_HOME", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	type connectionObservation struct {
		count int
		err   error
	}
	observations := make(chan connectionObservation, 1)
	go func() {
		count := 0
		for {
			connection, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					observations <- connectionObservation{count: count}
				} else {
					observations <- connectionObservation{count: count, err: err}
				}
				return
			}
			count++
			if err := connection.Close(); err != nil {
				observations <- connectionObservation{count: count, err: err}
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		observation := <-observations
		if observation.err != nil {
			t.Errorf("observe materialize connections: %v", observation.err)
		}
		if observation.count != 0 {
			t.Errorf("unsigned read-only materialize opened %d network connections", observation.count)
		}
	})
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"manifest_version":1,"app":{"id":"library","version":"test","origin":"http://%s"},"tools":[`, listener.Addr()) +
		`{"name":"materialize","method":"GET","path":"/v1/materialize","auth":"none","input_schema":{"type":"object","properties":{"runtime_kind":{"type":"string"},"target":{"type":"string"}}},"params":[{"name":"runtime_kind","in":"query"},{"name":"target","in":"query"}],"mutation":false}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	err = withWorkingDir(home, func() error {
		_, _, err := executeInstalledManifestTool("library", []string{"materialize", "--runtime_kind", "claude-code", "--target", "local"})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "signed mutation") {
		t.Fatalf("unsigned local materialize error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(home, "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("unsigned response mutated AGENTS.md: %v", err)
	}
}
