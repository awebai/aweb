package handoff

import (
	"context"
	"testing"
	"time"
)

const backoffOperation = "b7b7b7b7-b7b7-47b7-87b7-b7b7b7b7b7b7"

func awaitFor(t *testing.T, stub *signerStub, interval, lifetime time.Duration, woken <-chan struct{}) (*Receipt, error, time.Duration) {
	t.Helper()
	var opened string
	opts := stub.options(&opened)
	opts.PollInterval = interval
	started := time.Now()
	receipt, err := awaitReceipt(context.Background(), opts, backoffOperation, started.Add(lifetime), woken)
	return receipt, err, time.Since(started)
}

func TestAPendingOperationIsReadLessOftenTheLongerItWaits(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt)
	// Without backing off this is about 65 reads; doubling from 10 ms is 7.
	_, err, _ := awaitFor(t, stub, 10*time.Millisecond, 650*time.Millisecond, nil)
	if ErrorCode(err) != "operation_expired" || stub.reads > 9 {
		t.Fatalf("err %v after %d reads", err, stub.reads)
	}
}

func TestTheBackoffStopsGrowingAtItsCap(t *testing.T) {
	original := pollCap
	pollCap = 40 * time.Millisecond
	t.Cleanup(func() { pollCap = original })
	stub := newSignerStub(t, pendingReceipt)
	// 10, 20, then every 40 ms: about 17 reads in 650 ms.
	_, err, _ := awaitFor(t, stub, 10*time.Millisecond, 650*time.Millisecond, nil)
	if ErrorCode(err) != "operation_expired" || stub.reads < 12 || stub.reads > 20 {
		t.Fatalf("err %v after %d reads", err, stub.reads)
	}
}

func TestAnUnhintedUnavailableReceiptBacksOffToo(t *testing.T) {
	stub := newSignerStub(t, "!503:receipt_unavailable")
	_, err, _ := awaitFor(t, stub, 10*time.Millisecond, 650*time.Millisecond, nil)
	if ErrorCode(err) != "receipt_unavailable" || stub.reads > 9 {
		t.Fatalf("err %v after %d reads", err, stub.reads)
	}
}

func TestAWakeReadsAtOnceInsteadOfWaitingOutTheBackoff(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	woken := make(chan struct{}, 1)
	go func() { time.Sleep(50 * time.Millisecond); woken <- struct{}{} }()
	receipt, err, took := awaitFor(t, stub, 400*time.Millisecond, 2*time.Second, woken)
	if err != nil || receipt.State != "committed" || took > 250*time.Millisecond || stub.reads != 2 {
		t.Fatalf("receipt %+v err %v after %s and %d reads", receipt, err, took, stub.reads)
	}
}

func TestAClosedWakeCannotMakeATightReadLoop(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt)
	woken := make(chan struct{})
	close(woken)
	_, err, _ := awaitFor(t, stub, 10*time.Millisecond, 650*time.Millisecond, woken)
	if ErrorCode(err) != "operation_expired" || stub.reads > 10 {
		t.Fatalf("err %v after %d reads", err, stub.reads)
	}
}

func TestAWakeDoesNotCutShortTheServicesRetryAfter(t *testing.T) {
	stub := newSignerStub(t, "!429:rate_limited:1", committedReceipt)
	woken := make(chan struct{}, 1)
	woken <- struct{}{}
	receipt, err, took := awaitFor(t, stub, 10*time.Millisecond, 3*time.Second, woken)
	if err != nil || receipt.State != "committed" || took < time.Second || stub.reads != 2 {
		t.Fatalf("receipt %+v err %v after %s and %d reads", receipt, err, took, stub.reads)
	}
}

func TestABackedOffWaitEndsAtTheOperationsExpiry(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt)
	// Reads at 0 and 300 ms; the next doubled wait (600 ms) would end at 900 ms.
	_, err, took := awaitFor(t, stub, 300*time.Millisecond, 500*time.Millisecond, nil)
	if ErrorCode(err) != "operation_expired" || took > 700*time.Millisecond || stub.reads != 2 {
		t.Fatalf("err %v after %s and %d reads", err, took, stub.reads)
	}
}
