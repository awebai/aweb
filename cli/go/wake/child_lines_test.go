package wake

import (
	"io"
	"strings"
	"testing"
)

func TestChildReadersDrainOversizedLinesAndResume(t *testing.T) {
	for _, stderr := range []bool{false, true} {
		name := "stdout"
		if stderr {
			name = "stderr"
		}
		t.Run(name, func(t *testing.T) {
			child := &ChannelCoreChild{}
			reader, writer := io.Pipe()
			done := make(chan struct{})
			if stderr {
				go func() { child.readStderr(reader); close(done) }()
			} else {
				go child.readStatus(reader, done)
			}
			go func() {
				defer writer.Close()
				io.WriteString(writer, "{\"type\":\"status\",\"last_error\":\""+strings.Repeat("x", 128*1024)+"\"}\n")
				io.WriteString(writer, strings.Repeat("x", 2*1024*1024)+"\n")
				io.WriteString(writer, "{\"type\":\"status\",\"last_error\":\"after overflow\"}\n")
			}()
			defer reader.Close()
			waitForCond(t, "reader drains and resumes after oversized line", func() bool {
				child.mu.Lock()
				defer child.mu.Unlock()
				if stderr {
					return strings.Contains(child.lastStderr, "after overflow")
				}
				return child.st.LastError == "after overflow"
			})
			<-done
		})
	}
}

func TestChildStatusAcceptsLargeLine(t *testing.T) {
	child := &ChannelCoreChild{}
	message := strings.Repeat("x", 128*1024)
	done := make(chan struct{})
	child.readStatus(strings.NewReader("{\"type\":\"status\",\"last_error\":\""+message+"\"}\n"), done)
	if child.Status().LastError != message {
		t.Fatal("status line below 1 MiB was discarded")
	}
}
