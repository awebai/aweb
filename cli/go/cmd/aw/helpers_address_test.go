package main

import (
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestSelectionAddressFallsBackForEphemeralIdentity(t *testing.T) {
	t.Parallel()

	sel := &awconfig.Selection{
		NamespaceSlug:  "demo",
		DefaultProject: "demo-project",
		IdentityHandle: "alice",
		Custody:        "self",
		Lifetime:       "ephemeral",
	}
	if got := selectionAddress(sel); got != "demo/alice" {
		t.Fatalf("selectionAddress()=%q want %q", got, "demo/alice")
	}
}

func TestSelectionAddressFallsBackForManagedPermanentIdentity(t *testing.T) {
	t.Parallel()

	sel := &awconfig.Selection{
		NamespaceSlug:  "myteam.aweb.ai",
		DefaultProject: "myteam",
		IdentityHandle: "support",
		Custody:        "custodial",
		Lifetime:       "persistent",
	}
	if got := selectionAddress(sel); got != "myteam.aweb.ai/support" {
		t.Fatalf("selectionAddress()=%q want %q", got, "myteam.aweb.ai/support")
	}
}
