package awid

import (
	"context"
	"testing"
)

func TestBootstrapRedeemUnsupported(t *testing.T) {
	// A zero client has no transport or authority; retirement must refuse before I/O.
	out, err := new(Client).BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{Token: "obsolete"})
	if out != nil || err != ErrBootstrapTokensUnsupported {
		t.Fatalf("unsupported bootstrap returned %v, %v", out, err)
	}
	if err.Error() != "Bootstrap tokens are not supported; use a setup key from the dashboard or run `aw init --join-from`." {
		t.Fatalf("missing actionable bootstrap recovery: %v", err)
	}
}
