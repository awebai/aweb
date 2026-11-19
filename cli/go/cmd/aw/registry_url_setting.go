package main

import (
	"errors"
	"os"
	"strings"
)

var errLocalRegistryURL = errors.New("registry URL 'local' is not supported; use an explicit registry URL")

type registryURLSettingInput struct {
	ExplicitURL string
	DefaultURL  string
}

// resolveRegistryURLSetting selects the process setting before a caller hands
// it to awid's canonical registry URL owner. The local sentinel has no network
// destination; callers retain their command-specific recovery guidance.
func resolveRegistryURLSetting(input registryURLSettingInput) (string, error) {
	value := firstNonEmptyString(input.ExplicitURL, os.Getenv("AWID_REGISTRY_URL"), input.DefaultURL)
	if strings.EqualFold(value, "local") {
		return "", errLocalRegistryURL
	}
	return value, nil
}
