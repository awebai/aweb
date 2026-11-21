package testcapture

import (
	"io"
	"os"
	"strings"
	"testing"
)

// A pipe's buffer can be as small as 512 bytes, so a capture that read a pipe
// only after fn returned would block fn's first larger write forever.
func TestCaptureKeepsOutputLargerThanAPipe(t *testing.T) {
	payload := strings.Repeat("captured output line\n", 1<<16)
	for name, capture := range map[string]func(testing.TB, func()) string{
		"stdout": Stdout,
		"stderr": Stderr,
	} {
		got := capture(t, func() {
			stream := os.Stdout
			if name == "stderr" {
				stream = os.Stderr
			}
			if _, err := io.WriteString(stream, payload); err != nil {
				t.Errorf("%s write: %v", name, err)
			}
		})
		if got != payload {
			t.Fatalf("%s captured %d bytes, want %d", name, len(got), len(payload))
		}
	}
}
