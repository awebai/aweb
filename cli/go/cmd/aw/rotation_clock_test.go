package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func rotationPredecessor(t *testing.T, createdAt time.Time) (*awconfig.ResolvedIdentity, *awconfig.EncryptionKeyRecord) {
	t.Helper()
	home := t.TempDir()
	return &awconfig.ResolvedIdentity{WorkingDir: home, IdentityHome: home},
		&awconfig.EncryptionKeyRecord{KeyID: "sha256:predecessor", CreatedAt: createdAt.UTC().Format(time.RFC3339), AssertionPath: "missing-assertion.json"}
}

// A rotation whose clock advances only after its context is cancelled is
// cancelled: it never commits to a timestamp it read after cancellation.
func TestRotationCreatedAtHonoursCancellationBeforeAcceptingATimestamp(t *testing.T) {
	tied := time.Now().UTC().Truncate(time.Second)
	identity, predecessor := rotationPredecessor(t, tied)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readings := 0
	setEncryptionKeyClock(t, func() time.Time {
		readings++
		if readings == 1 {
			return tied
		}
		cancel()
		return tied.Add(time.Second)
	})
	createdAt, err := rotationCreatedAt(ctx, identity, predecessor)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled while the clock advanced: created_at=%s err=%v, want context.Canceled", createdAt, err)
	}
}

// The comparator sees the tied reading, waits, and returns the first reading
// in a later whole second.
func TestRotationCreatedAtWaitsPastThePredecessorSecond(t *testing.T) {
	tied := time.Now().UTC().Truncate(time.Second)
	identity, predecessor := rotationPredecessor(t, tied)
	var seen []time.Time
	setEncryptionKeyClock(t, func() time.Time {
		reading := tied.Add(400 * time.Millisecond)
		if len(seen) > 0 {
			reading = tied.Add(time.Second)
		}
		seen = append(seen, reading)
		return reading
	})
	createdAt, err := rotationCreatedAt(context.Background(), identity, predecessor)
	if err != nil || !createdAt.Equal(tied.Add(time.Second)) || len(seen) != 2 {
		t.Fatalf("created_at=%s err=%v readings=%v, want the second reading %s", createdAt, err, seen, tied.Add(time.Second))
	}
}

// A clock stuck in the predecessor's second is refused by the rotation's own
// budget with a live context, and by cancellation before that budget.
func TestRotationCreatedAtRefusesAStuckClock(t *testing.T) {
	stuck := time.Now().UTC().Truncate(time.Second)
	identity, predecessor := rotationPredecessor(t, stuck)
	setEncryptionKeyClock(t, func() time.Time { return stuck })

	started := time.Now()
	_, err := rotationCreatedAt(context.Background(), identity, predecessor)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "cannot rotate: the clock reads") || elapsed < rotationClockBudget || elapsed > rotationClockBudget+2*time.Second {
		t.Fatalf("stuck clock, live context: err=%v after %s, want the clock refusal after the %s budget", err, elapsed, rotationClockBudget)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	started = time.Now()
	_, err = rotationCreatedAt(ctx, identity, predecessor)
	elapsed = time.Since(started)
	if !errors.Is(err, context.Canceled) || elapsed >= rotationClockBudget {
		t.Fatalf("stuck clock, cancelled context: err=%v after %s, want context.Canceled before the budget", err, elapsed)
	}
}
