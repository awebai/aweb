package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestStdoutCaptureHandlesLargeOutput(t *testing.T) {
	want := strings.Repeat("captured stdout\n", 1<<19)
	got := captureStdout(t, func() {
		written, err := io.WriteString(os.Stdout, want)
		if err != nil {
			t.Fatal(err)
		}
		if written != len(want) {
			t.Fatalf("wrote %d stdout bytes, want %d", written, len(want))
		}
	})
	if got != want {
		t.Fatalf("captured stdout differs: got %d bytes, want %d", len(got), len(want))
	}
}
