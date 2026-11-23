package main

import (
	"fmt"
	"strings"
	"time"
)

type claimHumanTarget struct {
	Username string
	Email    string
}

// normalizeClaimHumanTarget supplies the trim/lower target used by both CLI
// adapters. Account syntax, reserved names and email policy belong to Cloud;
// the shared artifact signs these normalized values verbatim
// (docs/unowned-team-claim.md).
func normalizeClaimHumanTarget(input claimHumanTarget) claimHumanTarget {
	return claimHumanTarget{Username: strings.ToLower(strings.TrimSpace(input.Username)), Email: strings.ToLower(strings.TrimSpace(input.Email))}
}

type claimHumanTimestampInput struct {
	Timestamp string
	Now       time.Time
}

// checkClaimHumanTimestamp checks only the claim's 300-second carrier window,
// not controller authority (docs/unowned-team-claim.md).
func checkClaimHumanTimestamp(input claimHumanTimestampInput) error {
	if input.Now.IsZero() {
		return fmt.Errorf("current time is required to check a controller claim")
	}
	issued, err := time.Parse(time.RFC3339, strings.TrimSpace(input.Timestamp))
	if err != nil {
		return fmt.Errorf("invalid controller claim timestamp: %w; regenerate it with aw id team claim-human-request", err)
	}
	if input.Now.Sub(issued).Abs() > 300*time.Second {
		return usageError("controller claim timestamp is outside the 300-second window; regenerate it with aw id team claim-human-request")
	}
	return nil
}
