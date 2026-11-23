package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

type claimHumanControllerInput struct {
	Path   string
	Target claimHumanTarget
	Now    time.Time
}

// readClaimHumanControllerFile checks the shared artifact's integrity and claim
// binding. Its embedded key supplies no controller authority: only Cloud checks
// the registry-current controller before ownership effects
// (docs/unowned-team-claim.md).
func readClaimHumanControllerFile(input claimHumanControllerInput) (claim awid.SignedUnownedTeamClaim, resultErr error) {
	if strings.TrimSpace(input.Path) == "" {
		return claim, errors.New("controller claim file is required")
	}
	file, err := os.Open(input.Path)
	if err != nil {
		return claim, fmt.Errorf("read controller claim file %q: %w", input.Path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close controller claim file %q: %w", input.Path, err))
		}
	}()
	// Bound carrier I/O using the shared HTTP input budget; the artifact reader
	// owns and enforces its stricter protocol size limit.
	raw, err := awid.ReadAllBounded(file, awid.MaxResponseSize)
	if err != nil {
		return claim, fmt.Errorf("read controller claim file %q: %w", input.Path, err)
	}
	claim, err = awid.ParseUnownedTeamClaim(raw)
	if err != nil {
		return claim, fmt.Errorf("controller claim file %q: %w", input.Path, err)
	}
	if err := claim.VerifyIntegrity(); err != nil {
		return claim, fmt.Errorf("controller claim file %q: %w", input.Path, err)
	}
	if claim.Request.Username != input.Target.Username {
		return claim, usageError("controller claim username does not match this claim; regenerate it with aw id team claim-human-request for the intended username")
	}
	if claim.Request.Email != input.Target.Email {
		return claim, usageError("controller claim email does not match this claim; regenerate it with aw id team claim-human-request for the intended email")
	}
	if err := checkClaimHumanTimestamp(claimHumanTimestampInput{Timestamp: claim.Request.Timestamp, Now: input.Now}); err != nil {
		return claim, err
	}
	return claim, nil
}
