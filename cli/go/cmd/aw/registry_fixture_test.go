package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// newRegistryWithoutAddressesForTest is a reachable registry that knows no
// address. A send to a member of the sender's own namespace is then bound by
// the team roster (awid ChainResolver), as it is in production when the
// member has no registered address; an unreachable registry refuses instead.
func newRegistryWithoutAddressesForTest(t *testing.T) string {
	t.Helper()
	return newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})).URL
}

// newRegistryWithAddressesForTest is a registry that resolves each
// "domain/name" address to a fresh global identity, so a client binds a send
// to it and the server answers the send. Any other path is not found.
func newRegistryWithAddressesForTest(t *testing.T, addresses ...string) string {
	t.Helper()
	type identity struct{ didAW, didKey string }
	known := map[string]identity{}
	keys := map[string]string{}
	for _, address := range addresses {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		id := identity{didAW: awid.ComputeStableID(pub), didKey: awid.ComputeDIDKey(pub)}
		domain, name, ok := strings.Cut(address, "/")
		if !ok {
			t.Fatalf("address %q is not domain/name", address)
		}
		known["/v1/namespaces/"+domain+"/addresses/"+name] = id
		keys["/v1/did/"+id.didAW+"/key"] = id.didKey
	}
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := known[r.URL.Path]; ok {
			domain, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/namespaces/"), "/addresses/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-" + name,
				"domain":          domain,
				"name":            name,
				"did_aw":          id.didAW,
				"current_did_key": id.didKey,
				"reachability":    "public",
				"created_at":      "2026-11-18T00:00:00Z",
				"delivery":        map[string]any{"origin": server.URL, "source": "namespace"},
			})
			return
		}
		if didKey, ok := keys[r.URL.Path]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/key"), "current_did_key": didKey})
			return
		}
		http.NotFound(w, r)
	}))
	return server.URL
}
