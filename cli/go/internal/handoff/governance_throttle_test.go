package handoff

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// recordPauses replaces pause for one test: each wait aw would make is
// recorded and returned at once unless the context has ended, and the
// client's clock moves on by it.
func recordPauses(t *testing.T) *[]time.Duration {
	waits := &[]time.Duration{}
	var offset time.Duration
	originalPause, originalNow := pause, now
	pause = func(ctx context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		offset += d
		return ctx.Err()
	}
	now = func() time.Time { return time.Now().Add(offset) }
	t.Cleanup(func() { pause, now = originalPause, originalNow })
	return waits
}

func distinct(values []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func TestAThrottledReceiptReadWaitsItsHintAndRecoversWithinTheDeadline(t *testing.T) {
	waits := recordPauses(t)
	stub := newSignerStub(t, "!503:receipt_unavailable:7", committedReceipt)
	var opened string
	receipt, err := Approve(context.Background(), stub.options(&opened), "a1a1a1a1-a1a1-41a1-81a1-a1a1a1a1a1a1", revokeIntent())
	if err != nil || receipt.State != "committed" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}
	if !slices.Equal(*waits, []time.Duration{7 * time.Second}) || stub.reads != 2 || stub.posts.Load() != 1 {
		t.Fatalf("waits %v reads %d posts %d", *waits, stub.reads, stub.posts.Load())
	}
	if !distinct(stub.auths) {
		t.Fatalf("requests were not each signed: %v", stub.auths)
	}
}

func TestAThrottledResumeSendsTheSameBytesAgainAndAChangedActStaysAConflict(t *testing.T) {
	// Run 22: the changed-act Resume's own POST answered 503 with a 13 s hint.
	waits := recordPauses(t)
	const id = "a2a2a2a2-a2a2-42a2-82a2-a2a2a2a2a2a2"
	stub := newSignerStub(t, committedReceipt)
	var opened string
	var saved []byte
	opts := stub.options(&opened)
	opts.Save = func(_ string, body []byte) error { saved = append([]byte{}, body...); return nil }
	if receipt, err := Approve(context.Background(), opts, id, revokeIntent()); err != nil || receipt.State != "committed" {
		t.Fatalf("original: %+v %v", receipt, err)
	}
	changed := bytes.Replace(saved, []byte("human-role.revoke"), []byte("human-role.designate"), 1)
	stub.postThrottle = []string{"13"}
	reads := stub.reads
	var forgotten []string
	opts.Save = nil
	opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
	receipt, err := Resume(context.Background(), opts, changed)
	if ErrorCode(err) != "operation_conflict" || (receipt != nil && receipt.State == "committed") {
		t.Fatalf("a changed act became %+v %v", receipt, err)
	}
	if !slices.Equal(*waits, []time.Duration{13 * time.Second}) || stub.reads != reads || len(forgotten) != 0 {
		t.Fatalf("waits %v receipt reads %d->%d forgotten %v", *waits, reads, stub.reads, forgotten)
	}
	if n := len(stub.postBodies); n != 3 || !bytes.Equal(stub.postBodies[1], changed) || !bytes.Equal(stub.postBodies[2], changed) {
		t.Fatalf("posts %d, not the changed bytes twice", n)
	}
}

func TestALostPrepareRecoversThroughThrottlesWithOneOperation(t *testing.T) {
	waits := recordPauses(t)
	const id = "a3a3a3a3-a3a3-43a3-83a3-a3a3a3a3a3a3"
	stub := newSignerStub(t, "!503:receipt_unavailable:7", pendingReceipt, committedReceipt)
	stub.dropPrepare = true
	var opened string
	var saved []byte
	opts := stub.options(&opened)
	opts.Save = func(_ string, body []byte) error { saved = append([]byte{}, body...); return nil }
	receipt, err := Approve(context.Background(), opts, id, revokeIntent())
	if ErrorCode(err) != "prepare_unconfirmed" || receipt.State != "pending" {
		t.Fatalf("lost prepare: %+v %v", receipt, err)
	}
	opts.Save = nil
	stub.postThrottle = []string{"13"}
	receipt, err = Resume(context.Background(), opts, saved)
	if err != nil || receipt.State != "committed" || receipt.OperationID != id {
		t.Fatalf("resumed %+v %v", receipt, err)
	}
	if !slices.Equal(*waits, []time.Duration{7 * time.Second, 13 * time.Second}) {
		t.Fatalf("waits %v", *waits)
	}
	for i, body := range stub.postBodies {
		if !bytes.Equal(body, saved) {
			t.Fatalf("post %d sent other bytes than the saved request", i)
		}
	}
	if !distinct(stub.auths) {
		t.Fatalf("requests were not each signed: %v", stub.auths)
	}
}

func TestAHintPastTheOperationsExpiryEndsResumableWithoutWaiting(t *testing.T) {
	for _, hint := range []string{"17", "99999999999999999999", "9223372036"} {
		waits := recordPauses(t)
		stub := newSignerStub(t, "!503:receipt_unavailable:"+hint, committedReceipt)
		stub.expiresIn = 5 * time.Second
		var opened string
		var forgotten []string
		opts := stub.options(&opened)
		opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
		receipt, err := Approve(context.Background(), opts, "a4a4a4a4-a4a4-44a4-84a4-a4a4a4a4a4a4", revokeIntent())
		if ErrorCode(err) != "receipt_unavailable" || receipt == nil || receipt.State != "unknown" {
			t.Errorf("%s: %+v %v", hint, receipt, err)
		}
		if len(*waits) != 0 || stub.reads != 1 || len(forgotten) != 0 {
			t.Errorf("%s: waits %v reads %d forgotten %v", hint, *waits, stub.reads, forgotten)
		}
	}
}

func TestAPollIntervalPastTheExpiryStopsEvenWithoutAHint(t *testing.T) {
	waits := recordPauses(t)
	stub := newSignerStub(t, "!503:receipt_unavailable:1", committedReceipt)
	stub.expiresIn = 5 * time.Second
	var opened string
	opts := stub.options(&opened)
	opts.PollInterval = 10 * time.Second
	receipt, err := Approve(context.Background(), opts, "a5a5a5a5-a5a5-45a5-85a5-a5a5a5a5a5a5", revokeIntent())
	if ErrorCode(err) != "receipt_unavailable" || receipt.State != "unknown" || len(*waits) != 0 {
		t.Fatalf("%+v %v waits %v", receipt, err, *waits)
	}
}

func TestAThrottledPrepareBeyondItsRetryBudgetEndsResumable(t *testing.T) {
	waits := recordPauses(t)
	stub := newSignerStub(t, committedReceipt)
	stub.postThrottle = []string{"13", "13"}
	var opened string
	var forgotten []string
	opts := stub.options(&opened)
	opts.Save = func(string, []byte) error { return nil }
	opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
	opts.RetryWithin = 20 * time.Second
	_, err := Approve(context.Background(), opts, "a6a6a6a6-a6a6-46a6-86a6-a6a6a6a6a6a6", revokeIntent())
	if ErrorCode(err) != "receipt_unavailable" || opened != "" || len(forgotten) != 0 {
		t.Fatalf("err %v opened %q forgotten %v", err, opened, forgotten)
	}
	if !slices.Equal(*waits, []time.Duration{13 * time.Second}) || stub.posts.Load() != 2 {
		t.Fatalf("waits %v posts %d", *waits, stub.posts.Load())
	}
}

func TestAMalformedHintIsNoHint(t *testing.T) {
	for _, hint := range []string{"7.5", "-3", "soon", "Wed, 21 Oct 2099 07:28:00 GMT", " "} {
		waits := recordPauses(t)
		stub := newSignerStub(t, "!503:receipt_unavailable:"+hint, committedReceipt)
		var opened string
		if receipt, err := Approve(context.Background(), stub.options(&opened), "a7a7a7a7-a7a7-47a7-87a7-a7a7a7a7a7a7", revokeIntent()); err != nil || receipt.State != "committed" {
			t.Errorf("%q: %+v %v", hint, receipt, err)
		}
		if len(*waits) != 0 {
			t.Errorf("%q: waited %v", hint, *waits)
		}
		// On a prepare, a 503 without a usable hint stays a refusal: nothing is resent.
		stub = newSignerStub(t, committedReceipt)
		stub.postThrottle = []string{hint}
		if _, err := Approve(context.Background(), stub.options(&opened), "a8a8a8a8-a8a8-48a8-88a8-a8a8a8a8a8a8", revokeIntent()); ErrorCode(err) != "receipt_unavailable" || stub.posts.Load() != 1 {
			t.Errorf("%q prepare: %v posts %d", hint, err, stub.posts.Load())
		}
	}
}

func TestCancellingAHintedWaitKeepsTheSavedRequest(t *testing.T) {
	recordPauses(t)
	ctx, cancel := context.WithCancel(context.Background())
	pause = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	stub := newSignerStub(t, "!503:receipt_unavailable:7", committedReceipt)
	var opened string
	var forgotten []string
	opts := stub.options(&opened)
	opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
	receipt, err := Approve(ctx, opts, "a9a9a9a9-a9a9-49a9-89a9-a9a9a9a9a9a9", revokeIntent())
	if !errors.Is(err, context.Canceled) || receipt.State != "unknown" || len(forgotten) != 0 || stub.reads != 1 {
		t.Fatalf("%+v %v forgotten %v reads %d", receipt, err, forgotten, stub.reads)
	}
}

func TestAZeroHintStillWaitsThePollInterval(t *testing.T) {
	waits := recordPauses(t)
	stub := newSignerStub(t, committedReceipt)
	stub.postThrottle = []string{"0"}
	var opened string
	opts := stub.options(&opened)
	opts.PollInterval = 2 * time.Second
	if receipt, err := Approve(context.Background(), opts, "b1b1b1b1-b1b1-41b1-81b1-b1b1b1b1b1b1", revokeIntent()); err != nil || receipt.State != "committed" {
		t.Fatalf("%+v %v", receipt, err)
	}
	if !slices.Equal(*waits, []time.Duration{2 * time.Second}) || stub.posts.Load() != 2 {
		t.Fatalf("waits %v posts %d", *waits, stub.posts.Load())
	}

	// The same on the read that reconciles a lost prepare.
	waits = recordPauses(t)
	stub = newSignerStub(t, "!503:receipt_unavailable:0", committedReceipt)
	stub.dropPrepare = true
	opts = stub.options(&opened)
	opts.PollInterval = 2 * time.Second
	if receipt, err := Approve(context.Background(), opts, "b2b2b2b2-b2b2-42b2-82b2-b2b2b2b2b2b2", revokeIntent()); err != nil || receipt.State != "committed" {
		t.Fatalf("lost prepare: %+v %v", receipt, err)
	}
	if !slices.Equal(*waits, []time.Duration{2 * time.Second}) || stub.reads != 2 {
		t.Fatalf("lost prepare: waits %v reads %d", *waits, stub.reads)
	}
}

func TestAWaitThatOutrunsItsBoundSendsNoFurtherRequest(t *testing.T) {
	// The process sleeps longer than asked: the bound is checked again
	// before the next request, not only before the wait.
	recordPauses(t)
	var overslept time.Duration
	pause = func(_ context.Context, d time.Duration) error { overslept += d + 30*time.Second; return nil }
	now = func() time.Time { return time.Now().Add(overslept) }

	stub := newSignerStub(t, committedReceipt)
	stub.postThrottle = []string{"7"}
	var opened string
	opts := stub.options(&opened)
	opts.RetryWithin = 20 * time.Second
	if _, err := Approve(context.Background(), opts, "b3b3b3b3-b3b3-43b3-83b3-b3b3b3b3b3b3", revokeIntent()); ErrorCode(err) != "receipt_unavailable" || stub.posts.Load() != 1 {
		t.Fatalf("prepare: %v posts %d", err, stub.posts.Load())
	}

	overslept = 0
	stub = newSignerStub(t, "!503:receipt_unavailable:7", committedReceipt)
	stub.expiresIn = 30 * time.Second
	if receipt, err := Approve(context.Background(), stub.options(&opened), "b4b4b4b4-b4b4-44b4-84b4-b4b4b4b4b4b4", revokeIntent()); ErrorCode(err) != "receipt_unavailable" || receipt.State != "unknown" || stub.reads != 1 {
		t.Fatalf("receipt: %+v %v reads %d", receipt, err, stub.reads)
	}
}

func TestARetriedRequestThatHangsEndsAtTheInvocationsBound(t *testing.T) {
	// The retried prepare never answers: the invocation's bound cuts it off,
	// the lost answer's reconciliation shares that bound, and the saved
	// request is kept to resume.
	stub := newSignerStub(t, committedReceipt)
	stub.postThrottle = []string{"1"}
	stub.blockPrepare = true
	var opened string
	var forgotten []string
	opts := stub.options(&opened)
	opts.RetryWithin = 1500 * time.Millisecond
	opts.PollInterval = 10 * time.Millisecond
	opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
	start := time.Now()
	receipt, err := Approve(context.Background(), opts, "b5b5b5b5-b5b5-45b5-85b5-b5b5b5b5b5b5", revokeIntent())
	elapsed := time.Since(start)
	if ErrorCode(err) != "receipt_unavailable" || receipt == nil || receipt.State != "unknown" || len(forgotten) != 0 {
		t.Fatalf("%+v %v forgotten %v", receipt, err, forgotten)
	}
	if elapsed < time.Second || elapsed > 3*time.Second || stub.posts.Load() != 2 || opened != "" {
		t.Fatalf("ended after %v with %d posts, opened %q", elapsed, stub.posts.Load(), opened)
	}
}
