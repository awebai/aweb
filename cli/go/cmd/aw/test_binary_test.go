package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
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
	// A parallel fork must not inherit this executable's writable descriptor,
	// even briefly before exec closes it (golang/go#22315).
	syscall.ForkLock.RLock()
	destination, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		syscall.ForkLock.RUnlock()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	syscall.ForkLock.RUnlock()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}
