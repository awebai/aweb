package wake

import (
	"errors"
	"net"
	"testing"
	"time"
)

// An accepted connection is evidence of a peer, even when it cannot answer.
func TestControlExchangeFailureDoesNotProveDaemonAbsence(t *testing.T) {
	for _, name := range []string{"deadline", "closed", "unterminated-response"} {
		t.Run(name, func(t *testing.T) {
			store := shortTempStore(t)
			listener, err := net.Listen("unix", store.SocketPath())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			release := make(chan struct{})
			defer close(release)
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				if name == "deadline" {
					<-release
				}
				if name == "unterminated-response" {
					if _, err := conn.Write([]byte(`{"ok":true}`)); err != nil {
						conn.Close()
						done <- err
						return
					}
				}
				done <- conn.Close()
			}()
			_, err = callWithTimeout(store.SocketPath(), ControlRequest{Op: OpPause, Home: "/instance"}, 30*time.Millisecond)
			if err == nil || errors.Is(err, ErrDaemonDown) {
				t.Errorf("accepted peer failure = %v, want unavailable without absence proof", err)
			}
			if name != "deadline" {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
