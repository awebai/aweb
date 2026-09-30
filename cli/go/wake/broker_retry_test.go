package wake

import (
	"context"
	"fmt"
	awid "github.com/awebai/aw/awid"
	"testing"
	"time"
)

func TestStreamQuarantinesOnlyPermanentRegistrationErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 408, 409, 422, 429, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := newRecordingServer(t)
			server.status = code
			runner := newStreamRunner("key", "identity", "team", openerFor(t, server.URL), func(awid.AgentEvent) {}, func(string, ...any) {}, time.Now, time.Minute, time.Millisecond, 2*time.Millisecond)
			runner.start(context.Background())
			defer runner.stop()
			permanent := code == 401 || code == 403 || code == 404 || code == 422
			waitForCond(t, "HTTP error classified", func() bool {
				if permanent {
					return runner.snapshot().Phase == string(StreamQuarantined)
				}
				return server.openCount() >= 2
			})
			if permanent && server.openCount() != 1 {
				t.Fatal("permanent error was retried")
			}
			if !permanent && runner.snapshot().Phase == string(StreamQuarantined) {
				t.Fatal("retryable error quarantined")
			}
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
