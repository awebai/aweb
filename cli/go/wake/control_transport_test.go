package wake

import (
	"errors"
	"net"
	"os"
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
			t.Cleanup(func() {
				if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
			})
			release := make(chan struct{})

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
						done <- errors.Join(err, conn.Close())
						return
					}
				}
				done <- conn.Close()
			}()
			defer func() {
				close(release)
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			_, err = callWithTimeout(store.SocketPath(), ControlRequest{Op: OpPause, Home: "/instance"}, 30*time.Millisecond)
			if err == nil || errors.Is(err, ErrDaemonDown) {
				t.Errorf("accepted peer failure = %v, want unavailable without absence proof", err)
			}
		})
	}
}

func TestDaemonLockInspectionFailureIsNotAbsence(t *testing.T) {
	store := tempStore(t)
	if err := os.Mkdir(store.LockPath(), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LockOwner(store.LockPath()); err == nil {
		t.Fatal("invalid lock treated as proof of daemon absence")
	}
	if _, err := StatusFromStore(store, 128); err == nil {
		t.Fatal("status swallowed lock inspection failure")
	}
}
