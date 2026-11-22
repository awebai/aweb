package awid

import (
	"strings"
	"testing"
)

func TestRegistryPinRejectsNonOriginPathsAndCredentials(t *testing.T) {
	resolver := NewRegistryResolver(nil, nil)
	for _, input := range []string{"https://registry.example.test/prefix", "https://person:synthetic-secret@registry.example.test"} {
		err := resolver.TrustRegistryOrigin(input)
		if err == nil {
			t.Errorf("admitted invalid registry URL %q", input)
			continue
		}
		if !strings.Contains(err.Error(), "Use https://registry.example.test.") {
			t.Errorf("missing origin-form remedy: %v", err)
		}
		if strings.Contains(err.Error(), "synthetic-secret") {
			t.Errorf("userinfo leaked: %v", err)
		}
	}
}
