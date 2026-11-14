package handoff

import (
	"context"
	"strings"
	"testing"
)

func TestANoWaitApprovalShowsItsPageAndReadsTheReceiptOnce(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	var opened string
	opts := stub.options(&opened)
	opts.NoWait = true
	var presented *Prepared
	var shownPage string
	opts.OnPresented = func(prepared *Prepared, page string) { presented, shownPage = prepared, page }
	receipt, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if err != nil || receipt.State != "pending" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}
	if _, called := stub.prepared["redirect_uri"]; called {
		t.Fatalf("a no-wait approval sent a callback: %v", stub.prepared)
	}
	if presented == nil || presented.OperationID != "11111111-1111-4111-8111-111111111111" || !strings.HasSuffix(shownPage, "/human/handoff/h1") || opened != shownPage {
		t.Fatalf("presented %+v page %q opened %q", presented, shownPage, opened)
	}
	if stub.reads != 1 {
		t.Fatalf("%d receipt reads, want 1", stub.reads)
	}
}

func TestANoWaitResumeOfADecidedOperationSettlesItsReceipt(t *testing.T) {
	for receipt, code := range map[string]string{committedReceipt: "", refusedReceipt: "human_refused"} {
		stub := newSignerStub(t, receipt)
		var opened string
		opts := stub.options(&opened)
		opts.NoWait = true
		saved := []byte(`{"operation_id":"11111111-1111-4111-8111-111111111111","operation":"human-role.revoke","variant":"default","approval_format":"intent_v1",` +
			`"scope":{"v":1,"kind":"protected_key","service_id":"svc","authority":{"kind":"team_controller","id":"h:example.com","domain":"example.com"}},` +
			`"audience":"https://console.example","subject":{"app_id":"example","installation_id":"i","role":"example.owner","principal":"did:aw:holder"}}`)
		got, err := Resume(context.Background(), opts, saved)
		if ErrorCode(err) != code || got == nil || stub.reads != 1 {
			t.Errorf("%s: receipt %+v err %v after %d reads", receipt, got, err, stub.reads)
		}
	}
}

func TestANoWaitReceiptThatCannotBeReadIsUnknownNotPending(t *testing.T) {
	stub := newSignerStub(t, "!503:receipt_unavailable")
	var opened string
	opts := stub.options(&opened)
	opts.NoWait = true
	receipt, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if ErrorCode(err) != "receipt_unavailable" || receipt == nil || receipt.State != "unknown" || stub.reads != 1 {
		t.Fatalf("receipt %+v err %v after %d reads", receipt, err, stub.reads)
	}
}
