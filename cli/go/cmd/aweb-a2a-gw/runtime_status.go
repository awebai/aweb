package main

// Health fields keep their deployed JSON strings; each producer owns a named
// vocabulary so configuration-fetch and identity states cannot be interchanged.
type runtimeHealthStatus string

const (
	runtimeHealthy   runtimeHealthStatus = "healthy"
	runtimePending   runtimeHealthStatus = "pending"
	runtimeUnhealthy runtimeHealthStatus = "unhealthy"
)

type managedFetchStatus string

const (
	managedFetchOK      managedFetchStatus = "ok"
	managedFetchPending managedFetchStatus = "pending"
	managedFetchStale   managedFetchStatus = "stale"
)

type gatewayIdentityStatus string

const (
	gatewayIdentityActive    gatewayIdentityStatus = "active"
	gatewayIdentityMissing   gatewayIdentityStatus = "missing"
	gatewayIdentityWorkspace gatewayIdentityStatus = "workspace"
)

type registryHealthStatus string

const (
	registryMissingURL          registryHealthStatus = "missing_registry_url"
	registryUnreachable         registryHealthStatus = "unreachable"
	registryUnhealthy           registryHealthStatus = "unhealthy"
	registryMissingVersion      registryHealthStatus = "missing_version"
	registryVersionBelowMinimum registryHealthStatus = "version_below_minimum"
	registryResponseUnreadable  registryHealthStatus = "response_unreadable"
	registryResponseTooLarge    registryHealthStatus = "response_too_large"
	registryResponseMalformed   registryHealthStatus = "response_malformed"
)

type managedFetchFailurePolicy uint8

const (
	managedStartDegraded managedFetchFailurePolicy = iota
	managedKeepCurrentSnapshot
)
