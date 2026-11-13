package awid

// routeUntrustedRegistriesToInjectedClient makes every registry origin in
// this test reach the client's injected HTTP client, as before registry
// pinning. Tests of the pinning itself do not use it.
func routeUntrustedRegistriesToInjectedClient(c *RegistryClient) {
	if c != nil && c.Resolver != nil {
		c.Resolver.pinnedHTTPClient = c.httpClient()
	}
}

// routeUntrustedResolverRegistriesToInjectedClient makes every registry
// origin in this test reach the resolver's injected HTTP client, as before
// registry pinning. Tests of the pinning itself do not use it.
func routeUntrustedResolverRegistriesToInjectedClient(r *RegistryResolver) {
	if r != nil {
		r.pinnedHTTPClient = r.HTTPClient
	}
}
