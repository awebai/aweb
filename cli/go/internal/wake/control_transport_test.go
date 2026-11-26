package wake

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
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
			if err := os.Chmod(store.SocketPath(), 0600); err != nil {
				t.Fatal(err)
			}
			accepted := make(chan struct{})
			release := make(chan struct{})

			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
					done <- errors.Join(err, conn.Close())
					return
				}
				line, err := bufio.NewReader(conn).ReadBytes('\n')
				if err != nil {
					done <- errors.Join(err, conn.Close())
					return
				}
				var request ControlRequest
				if err := json.Unmarshal(line, &request); err != nil {
					done <- errors.Join(err, conn.Close())
					return
				}
				if request.Op != OpPause || request.Home != "/instance" {
					done <- errors.Join(errors.New("wrong control request"), conn.Close())
					return
				}
				close(accepted)
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
				if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				case <-time.After(2 * time.Second):
					t.Error("control peer did not stop")
				}
			}()
			_, err = callWithTimeout(store.SocketPath(), ControlRequest{Op: OpPause, Home: "/instance"}, 100*time.Millisecond)
			select {
			case <-accepted:
			case <-time.After(time.Second):
				t.Error("control peer did not receive the request")
			}
			if name == "deadline" && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("want read deadline, got %v", err)
			}
			if name != "deadline" && !errors.Is(err, io.EOF) {
				t.Errorf("want incomplete response EOF, got %v", err)
			}
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
