package main

import (
	"context"
	"errors"
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
	return resolveRegistryAuthority(context.Background(), registryAuthorityRequest{
		Kind: registryProcessSetting, Override: input.ExplicitURL, DefaultURL: input.DefaultURL,
	})
}
