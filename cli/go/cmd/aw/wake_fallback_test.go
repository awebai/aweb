package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/wake"
)

func TestWakeMutationFallbackRequiresAndHoldsDaemonLock(t *testing.T) {
	for _, state := range []string{"absent", "held", "unreadable-lock"} {
		t.Run(state, func(t *testing.T) {
			store, err := wake.NewStore(filepath.Join(t.TempDir(), "wake"))
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "held":
				lock, err := wake.AcquireLock(store.LockPath())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := lock.Release(); err != nil {
						t.Error(err)
					}
				})
			case "unreadable-lock":
				if err := os.Mkdir(store.LockPath(), 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			_, err = wakeCallOrFallback(store, wake.ControlRequest{Op: wake.OpPause, Home: "/instance"}, func() error {
				calls++
				lock, err := wake.AcquireLock(store.LockPath())
				if err == nil {
					if err := lock.Release(); err != nil {
						return err
					}
					t.Error("daemon can start during fallback write")
					return nil
				}
				var running *wake.ErrDaemonAlreadyRunning
				if !errors.As(err, &running) {
					return err
				}
				return nil
			})
			if state == "absent" {
				if err != nil || calls != 1 {
					t.Fatalf("absent daemon fallback: calls=%d err=%v", calls, err)
				}
			} else if err == nil || calls != 0 {
				t.Fatalf("%s daemon: fallback calls=%d err=%v", state, calls, err)
			}
		})
	}
}
