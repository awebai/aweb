// Package testcapture captures process output for serial tests.
package testcapture

import (
	"io"
	"os"
	"testing"
)

// Stdout captures complete output from fn without pipe backpressure. Callers
// must run serially because os.Stdout belongs to the whole process.
func Stdout(t testing.TB, fn func()) string {
	t.Helper()
	return capture(t, &os.Stdout, fn)
}

// Stderr captures complete output from fn without pipe backpressure. Callers
// must run serially because os.Stderr belongs to the whole process.
func Stderr(t testing.TB, fn func()) string {
	t.Helper()
	return capture(t, &os.Stderr, fn)
}

func capture(t testing.TB, stream **os.File, fn func()) string {
	t.Helper()
	captured, err := os.CreateTemp(t.TempDir(), "captured-output-*")
	if err != nil {
		t.Fatal(err)
	}
	saved := *stream
	*stream = captured
	defer func() {
		*stream = saved
		if err := captured.Close(); err != nil {
			t.Errorf("close captured output: %v", err)
		}
	}()
	fn()
	*stream = saved
	if _, err := captured.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(captured)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
