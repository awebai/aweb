package main

import (
	"strings"
	"testing"
)

func TestInitRejectsRegistryFormsThatFailOnTheFirstRead(t *testing.T) {
	previous := initAWIDRegistry
	t.Cleanup(func() { initAWIDRegistry = previous })
	for _, input := range []string{"https://registry.example.test/prefix", "https://person:synthetic-secret@registry.example.test"} {
		initAWIDRegistry = input
		got, err := resolveInitAWIDRegistryURL()
		if err == nil {
			t.Errorf("init accepted registry %q; first-read compatibility must be checked before storing it (got %q)", input, got)
			continue
		}
		if !strings.Contains(err.Error(), "Use https://registry.example.test.") {
			t.Errorf("missing origin-form remedy: %v", err)
		}
		if strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "person:") {
			t.Errorf("userinfo leaked in refusal: %v", err)
		}
	}
}

func TestInitCanonicalizesEquivalentRegistryAPIAliases(t *testing.T) {
	previous := initAWIDRegistry
	t.Cleanup(func() { initAWIDRegistry = previous })
	for _, input := range []string{"https://REGISTRY.example.test:443", "https://REGISTRY.example.test:443/", "https://REGISTRY.example.test:443/api", "https://REGISTRY.example.test:443/api/"} {
		initAWIDRegistry = input
		got, err := resolveInitAWIDRegistryURL()
		if err != nil || got != "https://registry.example.test" {
			t.Errorf("%q: got %q, %v", input, got, err)
		}
	}
}
