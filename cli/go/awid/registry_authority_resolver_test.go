package awid

import (
	"context"
	"net"
	"testing"
)

// These resolver seam controls check routing and its cache. The TXT stand-in
// is not real DNS authority or identity-verification evidence.
func TestRegistrySelectionAdministrativePinDoesNotAskDNS(t *testing.T) {
	dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{
		"_awid.foreign.example": {err: &net.DNSError{Err: "refused"}},
	}}
	client := NewAWIDRegistryClient(nil, dns)
	selected, err := client.SelectRegistry(context.Background(), RegistryAuthorityInput{
		Environment: RegistryProduction, Operation: RegistryAdministrative,
		Domain: "foreign.example", ConfiguredOrigin: "https://configured.registry.example/api/",
	})
	if err != nil || selected.Origin != "https://configured.registry.example" || selected.Provenance != RegistrySourceConfigured || dns.callCount() != 0 {
		t.Fatalf("administrative routing changed: %+v, %v, DNS calls %d", selected, err, dns.callCount())
	}
}

func TestRegistrySelectionCachedDNSAbsenceRemainsUnknown(t *testing.T) {
	dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{}}
	client := NewAWIDRegistryClient(nil, dns)
	in := RegistryAuthorityInput{
		Environment: RegistryProduction, Operation: RegistryOutboundRead,
		Domain: "foreign.example", IdentityDomain: "home.example", ConfiguredOrigin: "https://home.registry.example",
	}
	for range 2 {
		selected, err := client.SelectRegistry(context.Background(), in)
		if err != nil || selected.Origin != in.ConfiguredOrigin || selected.Provenance != RegistrySourceFallback || selected.AuthorityEstablished || selected.NotFound != RegistryUnknownAbsence {
			t.Fatalf("absence became authoritative: %+v, %v", selected, err)
		}
	}
	if dns.callCount() != 1 {
		t.Fatalf("DNS absence cache not reused: %d", dns.callCount())
	}
}

func TestRegistrySelectionFoundRecordKeepsItsSourceOnCacheHit(t *testing.T) {
	const origin = "https://foreign.registry.example"
	dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{
		"_awid.foreign.example": {records: []string{"awid=v1; controller=did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd; registry=" + origin + ";"}},
	}}
	client := NewAWIDRegistryClient(nil, dns)
	in := RegistryAuthorityInput{
		Environment: RegistryProduction, Operation: RegistryOutboundRead,
		Domain: "foreign.example", IdentityDomain: "home.example", ConfiguredOrigin: "https://home.registry.example",
	}
	for range 2 {
		selected, err := client.SelectRegistry(context.Background(), in)
		if err != nil || selected.Origin != origin || selected.Provenance != RegistrySourceDiscovery || !selected.AuthorityEstablished || selected.NotFound != RegistryAuthoritativeAbsence {
			t.Fatalf("record became a fallback: %+v, %v", selected, err)
		}
	}
	if dns.callCount() != 1 {
		t.Fatalf("record cache not reused: %d", dns.callCount())
	}
}
