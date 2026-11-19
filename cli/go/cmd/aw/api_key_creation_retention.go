package main

import (
	"fmt"
	"os"

	"github.com/awebai/aw/awconfig"
)

type apiKeyInitRecoveryState uint8

const (
	apiKeyInitRecoverable apiKeyInitRecoveryState = iota
	apiKeyInitReconciliationOnly
)

type apiKeyInitFailure struct {
	Cause error
	Home  awconfig.IdentityHome
	State apiKeyInitRecoveryState
}

func finalizeAPIKeyInitFailure(input apiKeyInitFailure) error {
	if input.Cause != nil && input.State == apiKeyInitRecoverable {
		if info, err := os.Lstat(apiKeyPartialInitPath(input.Home)); err == nil && info.Mode().IsRegular() {
			return fmt.Errorf("%w\n%s", input.Cause, partialInitGuidance(input.Cause))
		}
	}
	return input.Cause
}
