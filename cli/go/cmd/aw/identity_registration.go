package main

import "github.com/awebai/aw/awid"

// identityRegistration describes whether this creation needed and completed
// ID-certificate registration; membership alone does not establish attribution
// (docs/id-certificates.md#1-what-the-tree-proves).
type identityRegistration string

const (
	identityRegistrationUnknown     identityRegistration = "unknown"
	identityRegistrationRegistered  identityRegistration = "registered"
	identityRegistrationNotRequired identityRegistration = "not_required"
)

func responsibilityWithoutInstalledChain() *awid.IDChainResult {
	result := (awid.IDChainVerdict{Outcome: awid.IDChainOutcomeUnknown, Refusal: awid.IDRefusalLegacyNoChain}).Legacy()
	return &result
}
