package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Build current source once per package invocation, never reuse an installed aw
// or an artifact from another invocation. TestMain owns cleanup after all tests.
var awTestBinary struct {
	once      sync.Once
	sourceDir string
	env       []string
	dir       string
	path      string
	err       error
}

func buildAwBinary(t *testing.T, ctx context.Context, outPath string) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	awTestBinary.once.Do(func() {
		awTestBinary.dir, awTestBinary.err = os.MkdirTemp("", "aw-cmd-test-binary-")
		if awTestBinary.err != nil {
			return
		}
		name := "aw"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		awTestBinary.path = filepath.Join(awTestBinary.dir, name)
		// One caller's command deadline must not cancel the artifact needed by
		// every other test. The build itself remains bounded.
		buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		build := exec.CommandContext(buildCtx, "go", "build", "-o", awTestBinary.path, "./cmd/aw")
		build.Dir = awTestBinary.sourceDir
		build.Env = awTestBinary.env
		started := time.Now()
		if output, err := build.CombinedOutput(); err != nil {
			awTestBinary.err = fmt.Errorf("build CLI: %w\n%s", err, output)
		}
		fmt.Fprintf(os.Stderr, "shared test CLI build: %s\n", time.Since(started).Round(time.Millisecond))
	})
	if awTestBinary.err != nil {
		t.Fatal(awTestBinary.err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	// Copy instead of linking: tests may replace, truncate or remove their own
	// executable without mutating the source artifact or another test's copy.
	source, err := os.Open(awTestBinary.path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestAwBinaryFixtureCopiesAreIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	paths := []string{filepath.Join(root, "first"), filepath.Join(root, "second")}
	t.Run("parallel copies", func(t *testing.T) {
		for i := range paths {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()
				buildAwBinary(t, ctx, paths[i])
			})
		}
	})
	original, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], []byte("replaced executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	third := filepath.Join(root, "third")
	buildAwBinary(t, ctx, third)
	for _, path := range []string{paths[1], third} {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, original) {
			t.Fatalf("another test mutated executable %s: %v", path, err)
		}
		if runtime.GOOS == "windows" {
			// Go's exec lookup requires the native extension even for explicit paths.
			if err := os.Rename(path, path+".exe"); err != nil {
				t.Fatal(err)
			}
			path += ".exe"
		}
		if output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput(); err != nil {
			t.Fatalf("run independent source-built CLI: %v\n%s", err, output)
		}
	}
}
