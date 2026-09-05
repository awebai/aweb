package wake

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
)

// Reconnect bounds from docs/terminal-wake-broker.md §4.
//
// The broker closes at four minutes — channel-core's planned-close margin
// inside the server's five-minute cap — so the close is always the broker's,
// never a server EOF it has to classify. Backoff is 1 s doubling to 15 s with
// jitter, per identity: jitter is required at a hundred connections and
// neither cli/go/run/eventbus.go nor channel-core has it, and a ceiling above
// 15 s would spend a visible fraction of every five-minute cycle deaf.
//
// This is the part of eventbus.go the broker could not use as is (§7): its TTL
// is a 10-minute local deadline and its 250 ms→2 s backoff has no jitter. The
// stream *source* is reused unchanged through run.EventStreamOpener, and
// `aw run` is not touched.
const (
	DefaultStreamTTL  = 4 * time.Minute
	DefaultBackoffMin = 1 * time.Second
	DefaultBackoffMax = 15 * time.Second
)

// StreamPhase is a stream's reported condition.
type StreamPhase string

const (
	StreamStarting    StreamPhase = "starting"
	StreamLive        StreamPhase = "streaming"
	StreamRetrying    StreamPhase = "retrying"
	StreamQuarantined StreamPhase = "quarantined"
	StreamStopped     StreamPhase = "stopped"
)

type streamRunner struct {
	identityHome string
	open         run.EventStreamOpener
	onEvent      func(awid.AgentEvent)
	log          func(string, ...any)
	now          func() time.Time
	ttl          time.Duration
	backoffMin   time.Duration
	backoffMax   time.Duration

	mu          sync.Mutex
	phase       StreamPhase
	lastError   string
	unread      int
	connectedAt time.Time

	randMu sync.Mutex
	rng    *rand.Rand

	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

func newStreamRunner(identityHome string, open run.EventStreamOpener, onEvent func(awid.AgentEvent), log func(string, ...any), now func() time.Time, ttl, backoffMin, backoffMax time.Duration) *streamRunner {
	if ttl <= 0 {
		ttl = DefaultStreamTTL
	}
	if backoffMin <= 0 {
		backoffMin = DefaultBackoffMin
	}
	if backoffMax < backoffMin {
		backoffMax = DefaultBackoffMax
	}
	return &streamRunner{
		identityHome: identityHome,
		open:         open,
		onEvent:      onEvent,
		log:          log,
		now:          now,
		ttl:          ttl,
		backoffMin:   backoffMin,
		backoffMax:   backoffMax,
		phase:        StreamStarting,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(len(identityHome)))),
		done:         make(chan struct{}),
	}
}

func (s *streamRunner) start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go s.run(ctx)
}

// stop is safe on a runner that was never started, which is how a broker
// constructed but never run tears itself down.
func (s *streamRunner) stop() {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
			return
		}
		close(s.done)
	})
	<-s.done
}

func (s *streamRunner) snapshot() StreamStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StreamStatus{
		IdentityHome: s.identityHome,
		Phase:        string(s.phase),
		LastError:    s.lastError,
		UnreadCount:  s.unread,
		ConnectedAt:  s.connectedAt,
		Admitted:     true,
	}
}

func (s *streamRunner) setPhase(p StreamPhase, errText string) {
	s.mu.Lock()
	s.phase = p
	s.lastError = errText
	if p == StreamLive && s.connectedAt.IsZero() {
		s.connectedAt = s.now()
	}
	s.mu.Unlock()
}

func (s *streamRunner) noteUnread(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	s.unread = n
	s.mu.Unlock()
}

// jittered returns the sleep for one retry: between half and all of base.
func (s *streamRunner) jittered(base time.Duration) time.Duration {
	half := base / 2
	if half <= 0 {
		return base
	}
	s.randMu.Lock()
	extra := time.Duration(s.rng.Int63n(int64(half) + 1))
	s.randMu.Unlock()
	return half + extra
}

func (s *streamRunner) run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		s.mu.Lock()
		if s.phase != StreamQuarantined {
			s.phase = StreamStopped
		}
		s.mu.Unlock()
	}()

	delay := s.backoffMin
	recoveryPending := false
	outageReported := false

	for ctx.Err() == nil {
		deadline := s.now().Add(s.ttl)
		streamCtx, cancel := context.WithDeadline(ctx, deadline)
		source, err := s.open(streamCtx, deadline)
		if err != nil {
			cancel()
			if code, ok := awid.HTTPStatusCode(err); ok && code >= 400 && code < 500 {
				// One identity is quarantined and reported; the daemon and
				// every other stream keep running (§4).
				s.setPhase(StreamQuarantined, err.Error())
				s.log("stream quarantined identity_home=%s status=%d err=%v", s.identityHome, code, err)
				return
			}
			recoveryPending = true
			if !outageReported {
				outageReported = true
				s.setPhase(StreamRetrying, err.Error())
				s.log("stream outage identity_home=%s err=%v", s.identityHome, err)
			}
			if !sleepCtx(ctx, s.jittered(delay)) {
				return
			}
			delay = doubleUpTo(delay, s.backoffMax)
			continue
		}

		confirmed := false
		consumeErr := s.consume(streamCtx, source, func() {
			if confirmed {
				return
			}
			confirmed = true
			delay = s.backoffMin
			s.setPhase(StreamLive, "")
			if recoveryPending {
				recoveryPending = false
				outageReported = false
				s.log("stream reconnected identity_home=%s", s.identityHome)
				// One catch-up hint, not one per missed message (§6).
				s.onEvent(awid.AgentEvent{Type: awid.AgentEventChannelReconnected})
			}
		})
		plannedClose := streamCtx.Err() != nil && ctx.Err() == nil
		_ = source.Close()
		cancel()

		if ctx.Err() != nil {
			return
		}
		if plannedClose {
			// The broker's own four-minute close. Not an outage: it is
			// reopened immediately and the fresh stream's snapshot is what
			// re-raises anything still unread.
			continue
		}
		if consumeErr != nil {
			recoveryPending = true
			if !outageReported {
				outageReported = true
				s.setPhase(StreamRetrying, consumeErr.Error())
				s.log("stream outage identity_home=%s err=%v", s.identityHome, consumeErr)
			}
			if !sleepCtx(ctx, s.jittered(delay)) {
				return
			}
			delay = doubleUpTo(delay, s.backoffMax)
		}
	}
}

func (s *streamRunner) consume(ctx context.Context, source awid.EventSource, confirm func()) error {
	for ctx.Err() == nil {
		ev, err := source.Next(ctx)
		if err != nil {
			return err
		}
		confirm()
		if ev == nil {
			continue
		}
		switch ev.Type {
		case awid.AgentEventConnected:
			// Informational; the bus in cli/go/run drops it, and the broker
			// wants it only as a log line (§2).
			s.log("stream connected identity_home=%s agent=%s", s.identityHome, ev.AgentID)
			continue
		case awid.AgentEventError:
			s.log("stream error event identity_home=%s detail=%s", s.identityHome, truncateLog(string(ev.Raw)))
			continue
		}
		s.noteUnread(ev.UnreadCount)
		s.onEvent(*ev)
	}
	return ctx.Err()
}

func doubleUpTo(delay, max time.Duration) time.Duration {
	next := delay * 2
	if next <= 0 || next > max {
		return max
	}
	return next
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func truncateLog(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
