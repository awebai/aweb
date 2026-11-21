package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A pinned sender whose address the registry no longer has signed with the
// key this client pinned for it: that is not a forgery, and it is not current
// verification either. It is verification_stale, for a message arriving now
// and one read again later alike (Antares 2e8881d7; docs/trust-model.md:588-590).
// A registry that cannot be reached keeps a pinned sender verified
// (docs/trust-model.md:554-556).
func TestPinnedSenderWhoseAddressTheRegistryNoLongerHasIsStale(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(pub)
	for _, tc := range []struct {
		name           string
		registryStatus int
		want           VerificationStatus
	}{
		{name: "no such address", registryStatus: http.StatusNotFound, want: VerificationStale},
		{name: "registry unreachable", registryStatus: http.StatusServiceUnavailable, want: Verified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.registryStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": http.StatusText(tc.registryStatus)})
			}))
			t.Cleanup(registry.Close)
			pins := NewPinStore()
			pins.StorePin(senderDID, "retired.example/alice", "", "")
			pins.Pins[senderDID].DIDKey = senderDID
			pins.Pins[senderDID].ConfirmedBy = "registry"
			c, err := New("http://example")
			if err != nil {
				t.Fatal(err)
			}
			c.SetPinStore(pins, "")
			registryResolver := NewRegistryResolver(nil, nil)
			routeUntrustedResolverRegistriesToInjectedClient(registryResolver)
			if err := registryResolver.SetFallbackRegistryURL(registry.URL); err != nil {
				t.Fatal(err)
			}
			c.SetResolver(&ChainResolver{Registry: registryResolver, Pin: &PinResolver{Store: pins}})

			status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "retired.example/alice", senderDID, "", nil, nil, nil)

			if status != tc.want {
				t.Fatalf("status=%q, want %q", status, tc.want)
			}
			if pins.Addresses["retired.example/alice"] != senderDID {
				t.Fatalf("the pin changed: %v", pins.Addresses)
			}
		})
	}
}
