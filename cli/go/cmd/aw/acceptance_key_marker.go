package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
)

const acceptanceKeyMarkerName = "pending-hosted-accept"
const acceptanceKeyMarkerBody = "pending hosted accept\n"

// acceptanceMintedKey records the acceptance-minted, never-joined fact across
// a definitive refusal (docs/identity.md#acceptance-minted-key-recovery). The home is
// explicit; this marker never establishes attribution or registry authority.
type acceptanceMintedKey struct{ Home awconfig.IdentityHome }

func (marker acceptanceMintedKey) file() awconfig.RecoveryFile {
	return awconfig.RecoveryFile{Home: marker.Home, Name: acceptanceKeyMarkerName}
}

func (marker acceptanceMintedKey) present() (bool, error) {
	raw, err := marker.file().ReadBounded(256)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if string(raw) != acceptanceKeyMarkerBody {
		return false, errors.New("pending hosted accept marker is malformed; retain the identity home for reconciliation")
	}
	return true, nil
}

func (marker acceptanceMintedKey) save() error {
	if err := marker.file().Write([]byte(acceptanceKeyMarkerBody)); err != nil {
		return fmt.Errorf("write pending hosted accept marker: %w", err)
	}
	return nil
}

func (marker acceptanceMintedKey) remove() error { return marker.file().Remove() }

func (marker acceptanceMintedKey) require() error {
	present, err := marker.present()
	if err != nil {
		return err
	}
	if !present {
		return usageError("refusing to reuse existing %s: not a pending hosted accept (no %s marker); remove it if it is stale. If this directory has .aw/team-certs but no .aw/identity.yaml after a failed hosted global accept, rerun the same accept-invite command only when the marker is present; otherwise back up/remove the partial .aw/signing.key and .aw/team-certs state before retrying", filepath.Join(marker.Home.Root, "signing.key"), acceptanceKeyMarkerName)
	}
	return nil
}
