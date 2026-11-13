package main

import (
	"net/http"
	"strings"

	"github.com/awebai/aw/awid"
)

// The registries the operator named on the current command line. Together
// with the built-in default and AWID_REGISTRY_URL (both trusted inside awid),
// these are the only registry origins reached with the CLI's own HTTP client;
// every other origin, whether stored in identity, team or controller files,
// carried by an invite, returned by service discovery or learned from DNS, is
// pinned to public addresses.
func commandLineRegistryOrigins() []string {
	values := []string{
		a2aCardRegistry, a2aPublishRegistry, initAWIDRegistry,
		idAddressClaimRegistryURL, idChildRegistry, idCreateRegistryURL, idHumanInitRegistry,
		idNamespaceDeleteAddressRegistry, idNamespaceDeleteRegistry, idNamespacePrepareControllerRegistryURL,
		idNamespaceReaffirmRegistry, idParentRegistry,
		teamCreateRegistryURL, teamDeleteRegistryURL, teamFetchCertRegistry, teamHumanCreateRegistryURL,
		teamHumanRemoveRegistryURL, teamHumanReplaceKeyRegistryURL, teamMembersRegistryURL,
		teamRegisterRegistryURL, teamReissueCertRegistryURL, teamRemoveRegistryURL, teamRotateKeyRegistryURL,
		teamSetServerRegistryURL, teamShowServerRegistry, whoRegistry,
	}
	origins := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			origins = append(origins, value)
		}
	}
	return origins
}

// trustCommandLineRegistries marks the command line's registries as the
// operator's explicit choice on r. An invalid value is not trusted; the
// command that uses it reports it.
func trustCommandLineRegistries(r *awid.RegistryResolver) {
	if r == nil {
		return
	}
	for _, origin := range commandLineRegistryOrigins() {
		_ = r.TrustRegistryOrigin(origin)
	}
}

// newAWIDRegistryClient is awid.NewAWIDRegistryClient with the command
// line's registries trusted. Every registry client the CLI builds goes
// through it.
func newAWIDRegistryClient(httpClient *http.Client, txt awid.TXTResolver) *awid.RegistryClient {
	client := awid.NewAWIDRegistryClient(httpClient, txt)
	trustCommandLineRegistries(client.Resolver)
	return client
}

// newAWIDRegistryResolver is awid.NewRegistryResolver with the command
// line's registries trusted.
func newAWIDRegistryResolver(httpClient *http.Client, txt awid.TXTResolver) *awid.RegistryResolver {
	resolver := awid.NewRegistryResolver(httpClient, txt)
	trustCommandLineRegistries(resolver)
	return resolver
}
