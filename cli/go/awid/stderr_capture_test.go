package awid

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestCaptureStderrForTestLargeOutput(t *testing.T) {
	want := strings.Repeat("captured stderr\n", 1<<19)
	got := captureStderrForTest(t, func() {
		written, err := io.WriteString(os.Stderr, want)
		if err != nil {
			t.Fatal(err)
		}
		if written != len(want) {
			t.Fatalf("wrote %d stderr bytes, want %d", written, len(want))
		}
	})
	if got != want {
		t.Fatalf("captured stderr differs: got %d bytes, want %d", len(got), len(want))
	}
}
