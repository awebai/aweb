package main

import (
	"fmt"
	"github.com/awebai/aw/internal/pathpreflight"
	"os"
	"path/filepath"
	"strings"
)

// hostedAcceptPendingMarkerPath records that acceptance minted this key and it
// has not joined yet. It survives a definitive operation release and is removed
// on successful acceptance, so a correct invite reuses the same fresh key.
func hostedAcceptPendingMarkerPath(workingDir string, identityHomes ...string) string {
	root := filepath.Join(filepath.Clean(workingDir), ".aw")
	if len(identityHomes) > 0 && strings.TrimSpace(identityHomes[0]) != "" {
		root = filepath.Clean(identityHomes[0])
	}
	return filepath.Join(root, "pending-hosted-accept")
}

func preflightHostedAcceptPendingMarker(markerPath string) error {
	return pathpreflight.PreflightFile(markerPath, "hosted accept recovery marker", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func writeHostedAcceptPendingMarker(markerPath string) error {
	if err := preflightHostedAcceptPendingMarker(markerPath); err != nil {
		return err
	}
	if err := os.WriteFile(markerPath, []byte("pending hosted accept\n"), 0o600); err != nil {
		return fmt.Errorf("write pending hosted accept marker: %w", err)
	}
	return nil
}

func removeHostedAcceptPendingMarker(markerPath string) error {
	if err := preflightHostedAcceptPendingMarker(markerPath); err != nil {
		return err
	}
	if err := os.Remove(markerPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func statHostedAcceptPendingMarker(markerPath, keyPath string) error {
	if err := preflightHostedAcceptPendingMarker(markerPath); err != nil {
		return err
	}
	if _, err := os.Stat(markerPath); err != nil {
		if os.IsNotExist(err) {
			return usageError(
				"refusing to reuse existing %s: not a pending hosted accept (no %s marker); remove it if it is stale. If this directory has .aw/team-certs but no .aw/identity.yaml after a failed hosted global accept, rerun the same accept-invite command only when the marker is present; otherwise back up/remove the partial .aw/signing.key and .aw/team-certs state before retrying",
				keyPath,
				filepath.Base(markerPath),
			)
		}
		return err
	}
	return nil
}
