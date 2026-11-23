package awconfig

import "errors"

// RecoveryState distinguishes a possibly applied request and a retained
// confirmed result. Operation owners define their exact payloads.
type RecoveryState string

const (
	// RecoveryAttempted may have reached the remote effect and needs exact replay.
	RecoveryAttempted RecoveryState = "attempted"
	// RecoveryConfirmed retains the result needed to complete local installation.
	RecoveryConfirmed RecoveryState = "confirmed"
)

// RecoveryProgress is the common header for operation-specific creation and
// issuance recovery. It carries no key, certificate, recipient or authority;
// those belong to the operation's frozen context, prepared effect and result.
type RecoveryProgress struct {
	Version int           `json:"version" yaml:"version"`
	State   RecoveryState `json:"state" yaml:"state"`
}

var (
	// ErrRecoveryVersion refuses an unknown encoding without discarding it.
	ErrRecoveryVersion = errors.New("unsupported recovery version; retain the record for reconciliation")
	// ErrRecoveryState refuses unknown progress, never treating it as unused.
	ErrRecoveryState = errors.New("unknown recovery state; retain the record for reconciliation")
)

// Validate checks the shared version/state vocabulary. It never reflects a
// record's bytes into an error or infers absence from an unknown state.
func (progress RecoveryProgress) Validate() error {
	if progress.Version != 1 {
		return ErrRecoveryVersion
	}
	switch progress.State {
	case RecoveryAttempted, RecoveryConfirmed:
		return nil
	default:
		return ErrRecoveryState
	}
}
