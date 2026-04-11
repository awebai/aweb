package identityutil

import "testing"

func TestHandleFromAddressUsesLastSegment(t *testing.T) {
	t.Parallel()

	if got := HandleFromAddress("example.com/team/monitor"); got != "monitor" {
		t.Fatalf("got %q", got)
	}
	if got := HandleFromAddress("example.com~monitor"); got != "monitor" {
		t.Fatalf("got %q", got)
	}
	if got := HandleFromAddress("did:aw:monitor"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestMatchesSelfStrictPrefersStrongAddressMatch(t *testing.T) {
	t.Parallel()

	if !MatchesSelfStrict("monitor", "otherco/monitor", "", "did:key:someone-else", "monitor", "otherco/monitor", "did:key:self") {
		t.Fatal("expected address match to win")
	}
}

func TestMatchesSelfAllowsAddressHandleFallbackWhenOnlyAddressIsPresent(t *testing.T) {
	t.Parallel()

	if !MatchesSelf("", "example.com/monitor", "", "", "monitor", "", "did:key:self") {
		t.Fatal("expected address-handle fallback to match")
	}
}

func TestMatchesSelfFailsClosedOnConflictingDIDIdentity(t *testing.T) {
	t.Parallel()

	if MatchesSelf("monitor", "otherco/else", "", "did:key:someone-else", "monitor", "otherco/monitor", "did:key:self") {
		t.Fatal("expected conflicting DID identity to fail closed")
	}
}

func TestMatchesSelfStrictFailsClosedOnConflictingStrongIdentity(t *testing.T) {
	t.Parallel()

	if MatchesSelfStrict("monitor", "otherco/else", "", "did:key:someone-else", "monitor", "otherco/monitor", "did:key:self") {
		t.Fatal("expected conflicting strong identity to fail closed")
	}
}
