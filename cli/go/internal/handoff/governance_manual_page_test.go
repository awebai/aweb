package handoff

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// The released prepare shape has no indication of mailed notice delivery.
// The shared signer still supports embeddings with no mailed_approval_wait.
func TestSecurityReviewLegacySignerKeepsAManualApprovalPath(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt)
	var opened string
	opts := stub.options(&opened)
	opts.Open = nil // --no-browser, including a headless terminal.
	opts.NoWait = true
	var text bytes.Buffer
	opts.Notify = &text
	_, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "has emailed") {
		t.Errorf("a legacy prepare with no mail/delivery indicator claims mail was sent: %q", text.String())
	}
	if !strings.Contains(text.String(), opts.Human+"/handoff/h1") {
		t.Errorf("headless caller has no manual approval locator: %q", text.String())
	}
}
