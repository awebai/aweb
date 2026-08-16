package main

import (
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestSelectionAddressFallsBackForLocalIdentity(t *testing.T) {
	t.Parallel()

	sel := &awconfig.Selection{
		Domain:        "demo",
		Alias:         "alice",
		Custody:       "self",
		IdentityScope: "local",
	}
	if got := selectionAddress(sel); got != "demo/alice" {
		t.Fatalf("selectionAddress()=%q want %q", got, "demo/alice")
	}
}

func TestSelectionAddressFallsBackForManagedGlobalIdentity(t *testing.T) {
	t.Parallel()

	sel := &awconfig.Selection{
		Domain:        "myteam.aweb.ai",
		Alias:         "support",
		Custody:       "custodial",
		IdentityScope: "global",
	}
	if got := selectionAddress(sel); got != "myteam.aweb.ai/support" {
		t.Fatalf("selectionAddress()=%q want %q", got, "myteam.aweb.ai/support")
	}
}

func TestSelectionAddressPrefersExplicitAddress(t *testing.T) {
	t.Parallel()

	sel := &awconfig.Selection{
		Address:       "acme.com/support",
		Domain:        "demo",
		Alias:         "alice",
		Custody:       "self",
		IdentityScope: "global",
	}
	if got := selectionAddress(sel); got != "acme.com/support" {
		t.Fatalf("selectionAddress()=%q want %q", got, "acme.com/support")
	}
}
