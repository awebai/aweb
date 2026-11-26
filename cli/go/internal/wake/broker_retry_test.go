package wake

import (
	"context"
	"fmt"
	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/manualclock"
	"github.com/awebai/aw/run"
	"testing"
	"time"
)

// docs/event-stream-client-policy.md §3 and §4: 408, 409, 425 and 429 and any
// 5xx are retried on the transient delay; every other 4xx quarantines the
// stream, which is retried a minute later and not before.
func TestStreamQuarantinesOnlyPermanentRegistrationErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 408, 409, 422, 425, 429, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := newRecordingServer(t)
			server.status = code
			clock := manualclock.New(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
			clock.SetRandom(0.5)
			runner := newStreamRunner("key", "identity", "team", openerFor(t, server.URL), nil, func(awid.AgentEvent) {}, func(string, ...any) {}, clock.Now, run.StreamPolicyConfig{Timer: clock.Timer, Rand: clock.Random})
			runner.start(context.Background())
			defer runner.stop()
			permanent := code >= 400 && code < 500 && code != 408 && code != 409 && code != 425 && code != 429
			// The attempt's planned-close timer, then the wait before a retry.
			if !clock.AwaitStarted(2, 1) {
				t.Fatal("the stream is not waiting to retry")
			}
			status := runner.snapshot()
			wait, _ := clock.NextTimer()
			if permanent {
				if status.Phase != string(StreamRefused) || status.Admitted || status.Cause != fmt.Sprint(code) {
					t.Fatalf("status %+v, want refused by %d and not admitted", status, code)
				}
				if wait != 45*time.Second {
					t.Fatalf("retry in %s, want three quarters of a minute for the middle draw", wait)
				}
			} else {
				if status.Phase != string(StreamRetrying) || !status.Admitted {
					t.Fatalf("retryable error: status %+v, want retrying", status)
				}
				if wait != 750*time.Millisecond {
					t.Fatalf("retry in %s, want three quarters of a second for the middle draw", wait)
				}
			}
			if !status.NextAttemptAt.Equal(clock.Now().Add(wait)) {
				t.Fatalf("next attempt %s, want %s", status.NextAttemptAt, clock.Now().Add(wait))
			}
			clock.Advance(wait - time.Nanosecond)
			time.Sleep(20 * time.Millisecond)
			if server.openCount() != 1 {
				t.Fatal("retried before the wait was over")
			}
			clock.Advance(time.Nanosecond)
			waitForCond(t, "the retry", func() bool { return server.openCount() == 2 })
		})
	}
}

func TestChildBackoffNeverExceedsCapAfterJitter(t *testing.T) {
	for i := 0; i < 100; i++ {
		if got := jitteredBackoff(60*time.Second, 60*time.Second); got > 60*time.Second {
			t.Fatalf("backoff exceeds 60s cap: %s", got)
		}
	}
	if got := jitteredBackoff(time.Second, 60*time.Second); got < time.Second || got > 1200*time.Millisecond {
		t.Fatalf("jitter out of range: %s", got)
	}
}

func TestChildBackoffRetainsJitterAtAndAboveCap(t *testing.T) {
	for _, base := range []time.Duration{60 * time.Second, 120 * time.Second} {
		seen := map[time.Duration]bool{}
		for i := 0; i < 100; i++ {
			got := jitteredBackoff(base, 60*time.Second)
			if got < 48*time.Second || got > 60*time.Second {
				t.Fatalf("capped jitter out of range: %s", got)
			}
			seen[got] = true
		}
		if len(seen) == 1 {
			t.Fatal("backoff cap removed jitter and synchronized retries")
		}
	}
}
