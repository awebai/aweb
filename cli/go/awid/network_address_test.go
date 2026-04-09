package awid

import "testing"

func TestParseNetworkAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input     string
		wantOrg   string
		wantAlias string
		wantIsNet bool
	}{
		// Network addresses (org/alias)
		{"acme/researcher", "acme", "researcher", true},
		{"my-org/worker-1", "my-org", "worker-1", true},
		{"org123/bot", "org123", "bot", true},

		// Plain aliases (intra-project)
		{"researcher", "", "researcher", false},
		{"worker-1", "", "worker-1", false},
		{"bot", "", "bot", false},

		// Edge cases
		{"a/b", "a", "b", true},
		{"", "", "", false},

		// Malformed addresses (missing org or alias)
		{"/bob", "", "", false},
		{"org/", "", "", false},
		{"/", "", "", false},
		{"  /  ", "", "", false},
		{" acme / researcher ", "acme", "researcher", true},

		// Multiple slashes (invalid — org slugs and aliases don't contain slashes)
		{"org//alias", "", "", false},
		{"org/alias/extra", "", "", false},
		{"a/b/c/d", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			addr := ParseNetworkAddress(tc.input)
			if addr.IsNetwork != tc.wantIsNet {
				t.Fatalf("IsNetwork=%v, want %v", addr.IsNetwork, tc.wantIsNet)
			}
			if addr.Domain != tc.wantOrg {
				t.Fatalf("Domain=%q, want %q", addr.Domain, tc.wantOrg)
			}
			if addr.Alias != tc.wantAlias {
				t.Fatalf("Alias=%q, want %q", addr.Alias, tc.wantAlias)
			}
		})
	}
}

func TestNetworkAddressString(t *testing.T) {
	t.Parallel()

	addr := NetworkAddress{Domain: "acme", Alias: "researcher", IsNetwork: true}
	if s := addr.String(); s != "acme/researcher" {
		t.Fatalf("String()=%q", s)
	}

	addr2 := NetworkAddress{Alias: "worker", IsNetwork: false}
	if s := addr2.String(); s != "worker" {
		t.Fatalf("String()=%q", s)
	}
}
