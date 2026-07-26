//go:build awebtestpinstorecasbarrier

package main

import (
	"fmt"
	"os"
	"time"
)

const pinStoreCASTestBarrierTimeout = 15 * time.Second

func pinStoreCASPreLockHook() error {
	readyPath := os.Getenv("AW_PIN_STORE_CAS_TEST_READY")
	releasePath := os.Getenv("AW_PIN_STORE_CAS_TEST_RELEASE")
	if readyPath == "" && releasePath == "" {
		return nil
	}
	if readyPath == "" || releasePath == "" {
		return fmt.Errorf("pin-store CAS test barrier requires ready and release paths")
	}
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		return fmt.Errorf("signal pin-store CAS test readiness: %w", err)
	}

	deadline := time.Now().Add(pinStoreCASTestBarrierTimeout)
	for {
		if _, err := os.Stat(releasePath); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read pin-store CAS test release: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pin-store CAS test barrier timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
