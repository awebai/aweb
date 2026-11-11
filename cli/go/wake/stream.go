package wake

import (
	"context"
	"strings"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
)

// The broker's streams follow docs/event-stream-client-policy.md: when a
// connection closes, what its end means and how long to wait are decided by
// run.StreamPolicy, the implementation `aw run` uses too. This file keeps
// what is the broker's own: one runner per identity, the phase it reports in
// status, and the snapshot requests that reopen a live stream.
//
// The policy's bounds in short, for a hundred streams on one host: a planned
// close drawn between 3 min 30 s and 4 min, inside the server's five-minute
// cap, so streams that connected together drift apart; 1 s doubling to 15 s
// with jitter after a transient failure; 1 min doubling to 15 min after a
// refusal, with the identity read again before each attempt; and a connection
// closed after 75 s without a byte.
const (
	snapshotBackoffMin = 5 * time.Second
	snapshotBackoffMax = 5 * time.Minute
)

// StreamPhase is a stream's reported condition. A running stream is in one of
// the policy's three states (§8): streaming, retrying or refused. Starting is
// a stream that has not finished its first attempt; stopped is one its owner
// stopped.
type StreamPhase string

const (
	StreamStarting StreamPhase = "starting"
	StreamLive     StreamPhase = "streaming"
	StreamRetrying StreamPhase = "retrying"
	StreamRefused  StreamPhase = "refused"
	StreamStopped  StreamPhase = "stopped"
)

type streamRunner struct {
	key          string
	identityHome string
	teamID       string
	policy       *run.StreamPolicy
	onEvent      func(awid.AgentEvent)
	log          func(string, ...any)
	now          func() time.Time

	mu              sync.Mutex
	phase           StreamPhase
	cause           string
	nextAttempt     time.Time
	lastError       string
	lastErrorDetail *awid.ErrorDetail
	unread          int
	connectedAt     time.Time
	streamCancel    func()
	snapshotTimer   *time.Timer
	snapshotBackoff time.Duration

	cancel    context.CancelFunc
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// newStreamRunner builds one identity's stream. reload reads the identity's
// credentials again from its home; the policy calls it before each retry of a
// refused stream.
func newStreamRunner(key, identityHome, teamID string, open run.EventStreamOpener, reload run.StreamReload, onEvent func(awid.AgentEvent), log func(string, ...any), now func() time.Time, policy run.StreamPolicyConfig) *streamRunner {
	if policy.Now == nil {
		policy.Now = now
	}
	return &streamRunner{
		key:          key,
		identityHome: identityHome,
		teamID:       teamID,
		policy:       run.NewStreamPolicy(open, reload, policy),
		onEvent:      onEvent,
		log:          log,
		now:          now,
		phase:        StreamStarting,
		done:         make(chan struct{}),
	}
}

func (s *streamRunner) start(ctx context.Context) {
	s.startOnce.Do(func() {
		ctx, s.cancel = context.WithCancel(ctx)
		go s.run(ctx)
	})
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
		IdentityHome:    s.identityHome,
		TeamID:          s.teamID,
		Phase:           string(s.phase),
		Cause:           s.cause,
		NextAttemptAt:   s.nextAttempt,
		LastError:       s.lastError,
		LastErrorDetail: s.lastErrorDetail,
		UnreadCount:     s.unread,
		ConnectedAt:     s.connectedAt,
		// A refused identity is never shown as admitted (§8).
		Admitted: s.phase != StreamRefused,
	}
}

// refused reports whether the stream is quarantined.
func (s *streamRunner) refused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase == StreamRefused
}

// requestNow is an explicit request for the stream: a quarantined stream
// retries at once.
func (s *streamRunner) requestNow() {
	s.policy.Request()
}

// setPhase records the stream's phase and, for a stream that is not
// streaming, the end that put it there: its cause, the time of the next
// attempt, and the error as text and as its stable detail.
func (s *streamRunner) setPhase(p StreamPhase, end run.StreamEnd) {
	s.mu.Lock()
	s.phase = p
	s.cause, s.nextAttempt = end.Cause, end.NextAttempt
	s.lastError, s.lastErrorDetail = "", nil
	if end.Err != nil {
		detail := awid.DescribeError(end.Err)
		s.lastError, s.lastErrorDetail = end.Err.Error(), &detail
	}
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

// Coalesce exhausted-delivery requests into one fresh snapshot. Resume can
// advance that request immediately. Repeated refusal backs off independently
// of transport reconnects, and coalesced requests do not advance the backoff.
func (s *streamRunner) requestSnapshot(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if delay <= 0 {
		s.snapshotBackoff = 0
	}
	if s.streamCancel == nil {
		return
	} // no live attempt (between attempts, or stopped)
	if s.snapshotTimer != nil {
		if delay > 0 {
			return
		}
		s.snapshotTimer.Stop()
		s.snapshotTimer = nil
	}
	if delay <= 0 {
		s.streamCancel()
		return
	}
	if s.snapshotBackoff > delay {
		delay = s.snapshotBackoff
	}
	if delay > snapshotBackoffMax {
		delay = snapshotBackoffMax
	}
	s.snapshotBackoff = doubleUpTo(delay, snapshotBackoffMax)
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.snapshotTimer != timer {
			return
		}
		s.snapshotTimer = nil
		if s.streamCancel != nil {
			s.streamCancel()
		}
	})
	s.snapshotTimer = timer
}

// Successful input restores the initial retry window. If another refused
// message already scheduled a snapshot, keep that recovery but bring it forward.
func (s *streamRunner) resetSnapshotBackoff() {
	s.mu.Lock()
	s.snapshotBackoff = 0
	pending := s.snapshotTimer != nil
	if pending {
		s.snapshotTimer.Stop()
		s.snapshotTimer = nil
	}
	s.mu.Unlock()
	if pending {
		s.requestSnapshot(snapshotBackoffMin)
	}
}

func (s *streamRunner) clearSnapshotLocked() {
	if s.snapshotTimer != nil {
		s.snapshotTimer.Stop()
		s.snapshotTimer = nil
	}
	s.streamCancel = nil
}

func (s *streamRunner) run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		s.mu.Lock()
		s.clearSnapshotLocked()
		s.phase = StreamStopped
		s.cause, s.nextAttempt = "", time.Time{}
		s.mu.Unlock()
	}()

	outageReported := false

	for ctx.Err() == nil {
		conn := s.policy.Connect(ctx, func(endedRefusal string) {
			s.setPhase(StreamLive, run.StreamEnd{})
			switch {
			case endedRefusal != "":
				s.log("stream quarantine ended identity_home=%s cause=%s", s.identityHome, endedRefusal)
			case outageReported:
				s.log("stream reconnected identity_home=%s", s.identityHome)
			}
			outageReported = false
			// Transport recovery is diagnostic-only. The fresh stream snapshot
			// re-raises real actionable events; reconnect itself never becomes
			// terminal/model input.
		})
		s.mu.Lock()
		s.clearSnapshotLocked()
		s.streamCancel = conn.Reopen
		s.mu.Unlock()
		source, err := conn.Open()
		if err == nil {
			err = s.consume(conn, source)
			_ = source.Close()
		}
		s.mu.Lock()
		s.clearSnapshotLocked()
		s.mu.Unlock()

		end := conn.End(err)
		switch end.Kind {
		case run.StreamEndStopped:
			return
		case run.StreamEndPlannedClose:
			// The stream's own planned close, or a snapshot request. Not an
			// outage: it is reopened immediately and the fresh stream's
			// snapshot is what re-raises anything still unread.
		case run.StreamEndTransient:
			s.setPhase(StreamRetrying, end)
			if !outageReported {
				outageReported = true
				s.log("stream outage identity_home=%s err=%v", s.identityHome, end.Err)
			}
		case run.StreamEndRefused:
			// One identity is quarantined and reported; the daemon and every
			// other stream keep running. The quarantine is logged when it
			// starts; a retry that is refused again only moves the time of
			// the next attempt in status.
			s.setPhase(StreamRefused, end)
			if end.EnteredRefused {
				s.log("stream quarantined identity_home=%s cause=%s next_attempt=%s err=%v", s.identityHome, end.Cause, end.NextAttempt.UTC().Format(time.RFC3339), end.Err)
			}
		}
		if !s.policy.Wait(ctx, end) {
			return
		}
	}
}

func (s *streamRunner) consume(conn *run.StreamConnection, source awid.EventSource) error {
	ctx := conn.Context()
	for ctx.Err() == nil {
		ev, err := source.Next(ctx)
		if err != nil {
			return err
		}
		conn.Event(ev)
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

func truncateLog(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
