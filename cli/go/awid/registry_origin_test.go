package awid

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRegistryOriginCanonicalizationKeepsEquivalentAliases(t *testing.T) {
	for _, input := range []string{"https://Registry.example.test:443", "https://Registry.example.test:443/", "https://Registry.example.test:443/api", "https://Registry.example.test:443/api/"} {
		got, err := CanonicalRegistryServerOrigin(input)
		if err != nil || got != "https://registry.example.test" {
			t.Fatalf("%s: %q, %v", input, got, err)
		}
		if key := registryOriginKey(input); key != got {
			t.Fatalf("request %s != admission %s", got, key)
		}
	}
}

func TestRegistryURLRefusalsGiveCredentialFreeOriginRemedies(t *testing.T) {
	cases := []struct {
		input   string
		reason  RegistryURLRefusalReason
		message string
	}{
		{"https://registry.example.test/prefix", RegistryURLPath, "Registry URL must be an origin or its /api alias, without another path prefix."},
		{"https://registry.example.test?private=value", RegistryURLQuery, "Registry URL must not include a query."},
		{"https://registry.example.test#private", RegistryURLFragment, "Registry URL must not include a fragment."},
		{"https://person:synthetic-secret@registry.example.test", RegistryURLUserinfo, "Registry URL must not include credentials."},
		{"ftp://registry.example.test", RegistryURLScheme, "Registry URL scheme must be http or https."},
	}
	for _, tc := range cases {
		_, err := CanonicalRegistryServerOrigin(tc.input)
		var refusal *RegistryURLRefusal
		if !errors.As(err, &refusal) || refusal.Reason != tc.reason {
			t.Fatalf("wrong URL refusal: %v", err)
		}
		if err.Error() != tc.message+" Use https://registry.example.test." {
			t.Fatalf("wrong actionable sentence: %v", err)
		}
		if registryOriginKey(tc.input) != "" {
			t.Fatal("invalid URL became an admitted origin")
		}
		// The public read reaches the same refusal before constructing an HTTP request.
		client := NewAWIDRegistryClient(nil, nil)
		_, _, readErr := client.GetNamespaceAt(context.Background(), tc.input, "example.test")
		if !errors.As(readErr, &refusal) || refusal.Reason != tc.reason {
			t.Fatalf("public read diverged: %v", readErr)
		}
	}
	for _, input := range []string{"", "https://person:synthetic-secret@bad:port", "://bad"} {
		_, err := CanonicalRegistryServerOrigin(input)
		if err == nil || !strings.Contains(err.Error(), "Use an origin such as https://registry.example.") || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("unsafe malformed URL refusal: %v", err)
		}
	}
}

func TestCanonicalPrivateOriginDoesNotGrantAdministrativeTrust(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")
	origin, err := CanonicalRegistryServerOrigin("http://127.0.0.1:18010/api/")
	if err != nil || origin != "http://127.0.0.1:18010" {
		t.Fatalf("private origin syntax: %s, %v", origin, err)
	}
	resolver := NewRegistryResolver(nil, nil)
	if resolver.originTrusted(origin) {
		t.Fatal("URL canonicalization granted private trust")
	}
	if err := resolver.TrustRegistryOrigin("http://127.0.0.1:18010/api"); err != nil {
		t.Fatal(err)
	}
	if !resolver.originTrusted(origin) || resolver.originTrusted("http://127.0.0.1:18011") {
		t.Fatal("administrative pin lost its exact origin scope")
	}
}
