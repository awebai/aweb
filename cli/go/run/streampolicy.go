package run

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	awid "github.com/awebai/aw/awid"
)

// The event stream client policy, docs/event-stream-client-policy.md, sections
// 2 to 6, for the Go clients of GET /v1/events/stream: `aw run` (eventbus.go)
// and the `aw wake` broker (wake/stream.go). A client owns its loop, how it
// reports its state and how it is asked for a stream; every decision about
// when a connection closes, what an end means and how long to wait is made
// here.
const (
	// A connection's planned close is drawn uniformly between these (§2).
	StreamPlannedCloseMin = 3*time.Minute + 30*time.Second
	StreamPlannedCloseMax = 4 * time.Minute

	// The delay after a transient failure doubles between these (§3).
	StreamRetryDelayMin = 1 * time.Second
	StreamRetryDelayMax = 15 * time.Second

	// The delay after a refusal doubles between these (§4).
	StreamRefusedDelayMin = 1 * time.Minute
	StreamRefusedDelayMax = 15 * time.Minute

	// StreamRetryAfterMax caps Retry-After; a larger or unparsable value is
	// treated as this (§3).
	StreamRetryAfterMax = 5 * time.Minute

	// StreamSilenceLimit is how long an open stream may deliver no bytes: two
	// missed 30-second heartbeats plus 15 seconds (§6).
	StreamSilenceLimit = 75 * time.Second
)

// ErrStreamSilent ends a connection that read nothing for StreamSilenceLimit.
var ErrStreamSilent = errors.New("event stream silent for " + StreamSilenceLimit.String())

var (
	errStreamPlannedClose = errors.New("event stream planned close")
	errStreamEnded        = errors.New("event stream connection ended")
)

// StreamPolicyConfig is what the policy takes from outside. Every field has
// a real default; tests supply a clock they advance by hand.
type StreamPolicyConfig struct {
	Now func() time.Time
	// Timer returns a channel that receives after d and a function that
	// releases the timer.
	Timer func(d time.Duration) (<-chan time.Time, func())
	// Rand returns a uniform draw in [0, 1).
	Rand func() float64
}

func (c *StreamPolicyConfig) applyDefaults() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Timer == nil {
		c.Timer = func(d time.Duration) (<-chan time.Time, func()) {
			timer := time.NewTimer(d)
			return timer.C, func() { timer.Stop() }
		}
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
}

// StreamEndKind is what the end of one connection attempt means.
type StreamEndKind int

const (
	// StreamEndStopped: the stream's owner stopped it. Nothing else does (§1).
	StreamEndStopped StreamEndKind = iota
	// StreamEndPlannedClose: reconnect at once; not an outage (§2).
	StreamEndPlannedClose
	// StreamEndTransient: retry on the transient delay (§3).
	StreamEndTransient
	// StreamEndRefused: the stream is quarantined (§4).
	StreamEndRefused
)

func (k StreamEndKind) String() string {
	switch k {
	case StreamEndStopped:
		return "stopped"
	case StreamEndPlannedClose:
		return "planned close"
	case StreamEndTransient:
		return "transient"
	case StreamEndRefused:
		return "refused"
	default:
		return "unknown"
	}
}

// StreamEnd is how one connection attempt ended and what the client does next.
type StreamEnd struct {
	Kind StreamEndKind
	// Cause is the HTTP status, the terminal event's name or "silence". For a
	// refused stream it is the refusal that holds the quarantine. It is empty
	// for a transient failure that has no such name; Err describes it.
	Cause string
	Err   error
	// Wait is how long to wait before the next attempt, and NextAttempt when
	// that is. Both are zero for a planned close and a stopped stream.
	Wait        time.Duration
	NextAttempt time.Time
	// EnteredRefused is true for the end that starts a quarantine and false
	// for every refused retry inside it (§8).
	EnteredRefused bool
}

// ClassifyStreamFailure says whether a failed open or the error that ended an
// open stream is transient or a refusal, and names its cause.
//
// 408, 409, 425 and 429 describe a moment, not the caller: they are transient,
// as is every answer outside 4xx. Every other 4xx is a refusal. The grant
// terminal events are refusals, except verification_unavailable, which says
// the server could not check the grant. Everything else — a failure to open,
// an early end, a read error — is transient.
func ClassifyStreamFailure(err error) (StreamEndKind, string) {
	if status, ok := awid.HTTPStatusCode(err); ok {
		cause := strconv.Itoa(status)
		switch status {
		case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooEarly, http.StatusTooManyRequests:
			return StreamEndTransient, cause
		}
		if status >= 400 && status < 500 {
			return StreamEndRefused, cause
		}
		return StreamEndTransient, cause
	}
	var closed *awid.AgentEventStreamClosedError
	if errors.As(err, &closed) {
		if closed.Retryable() {
			return StreamEndTransient, closed.Event
		}
		return StreamEndRefused, closed.Event
	}
	return StreamEndTransient, ""
}

// streamRetryAfter is the minimum wait a failed open's Retry-After asks for:
// delta-seconds or an HTTP-date, capped at StreamRetryAfterMax. A value that
// is neither is treated as the cap. It is zero when the answer has no header.
func streamRetryAfter(err error, now time.Time) time.Duration {
	header, ok := awid.HTTPRetryAfter(err)
	if !ok {
		return 0
	}
	header = strings.TrimSpace(header)
	wait := StreamRetryAfterMax
	if isDigits(header) {
		// Digits that overflow are larger than the cap.
		if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds < int64(StreamRetryAfterMax/time.Second) {
			wait = time.Duration(seconds) * time.Second
		}
	} else if at, err := http.ParseTime(header); err == nil {
		wait = at.Sub(now)
	}
	if wait < 0 {
		return 0
	}
	if wait > StreamRetryAfterMax {
		return StreamRetryAfterMax
	}
	return wait
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// StreamPolicy holds one stream's reconnect state across its connections.
// One goroutine drives it: Connect, then the connection's Open and End, then
// Wait. Request and Refused may be called from any goroutine.
type StreamPolicy struct {
	cfg    StreamPolicyConfig
	reload func() (EventStreamOpener, error)

	mu           sync.Mutex
	open         EventStreamOpener
	retryDelay   time.Duration
	refusedDelay time.Duration
	refused      bool
	refusedCause string
	// request holds at most one explicit request made during a quarantine.
	request chan struct{}
}

// NewStreamPolicy returns the policy for one stream. open makes a connection.
// reload, when not nil, reads the stream's credentials again from where they
// are kept and returns the opener that uses them; it is called before every
// retry of a refused stream (§4). It must read the same identity from the
// same place: a refused client retries as itself or not at all (§5).
func NewStreamPolicy(open EventStreamOpener, reload func() (EventStreamOpener, error), cfg StreamPolicyConfig) *StreamPolicy {
	cfg.applyDefaults()
	return &StreamPolicy{
		cfg:          cfg,
		reload:       reload,
		open:         open,
		retryDelay:   StreamRetryDelayMin,
		refusedDelay: StreamRefusedDelayMin,
		request:      make(chan struct{}, 1),
	}
}

// Refused reports whether the stream is quarantined.
func (p *StreamPolicy) Refused() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refused
}

// Request is an explicit request for the stream. A quarantined stream retries
// at once and, if refused again, continues from the 1-minute delay (§4). It
// changes nothing for a stream that is not quarantined.
func (p *StreamPolicy) Request() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.refused {
		return
	}
	p.refusedDelay = StreamRefusedDelayMin
	select {
	case p.request <- struct{}{}:
	default:
	}
}

// Wait waits out end.Wait and reports whether to make another attempt: false
// only when ctx is done. A planned close does not wait. A quarantined stream's
// wait also ends on Request.
func (p *StreamPolicy) Wait(ctx context.Context, end StreamEnd) bool {
	if ctx.Err() != nil || end.Kind == StreamEndStopped {
		return false
	}
	if end.Kind == StreamEndPlannedClose {
		return true
	}
	var request <-chan struct{}
	if end.Kind == StreamEndRefused {
		request = p.request
	}
	fired, release := p.cfg.Timer(end.Wait)
	defer release()
	select {
	case <-ctx.Done():
		return false
	case <-fired:
		return true
	case <-request:
		return true
	}
}

// jittered draws a wait uniformly between half of delay and all of it.
func (p *StreamPolicy) jittered(delay time.Duration) time.Duration {
	half := delay / 2
	return half + time.Duration(p.cfg.Rand()*float64(delay-half))
}

// confirmed records that a stream is live: both delays return to their
// starts and a quarantine ends. It returns the cause of the quarantine it
// ended, or "".
func (p *StreamPolicy) confirmed() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retryDelay = StreamRetryDelayMin
	p.refusedDelay = StreamRefusedDelayMin
	cause := ""
	if p.refused {
		cause = p.refusedCause
	}
	p.refused, p.refusedCause = false, ""
	select {
	case <-p.request:
	default:
	}
	return cause
}

// failed records a failure and decides the wait before the next attempt.
//
// A quarantine holds until a stream is confirmed, so a transient failure
// inside one keeps the quarantine's pace and its cause.
func (p *StreamPolicy) failed(kind StreamEndKind, cause string, err error) StreamEnd {
	now := p.cfg.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	end := StreamEnd{Kind: kind, Cause: cause, Err: err}
	if kind == StreamEndRefused {
		end.EnteredRefused = !p.refused
		p.refused, p.refusedCause = true, cause
	}
	var delay time.Duration
	if p.refused {
		end.Kind, end.Cause = StreamEndRefused, p.refusedCause
		delay = p.refusedDelay
		p.refusedDelay = min(delay*2, StreamRefusedDelayMax)
	} else {
		delay = p.retryDelay
		p.retryDelay = min(delay*2, StreamRetryDelayMax)
	}
	end.Wait = streamRetryAfter(err, now) + p.jittered(delay)
	end.NextAttempt = now.Add(end.Wait)
	return end
}

// streamActivitySource is an event source that reports what it reads below
// the level of events. awid.AgentEventStream is one.
type streamActivitySource interface {
	OnRead(func())
	OnComment(func())
}

// StreamConnection is one connection attempt: its planned close, its silence
// watchdog and its confirmation.
type StreamConnection struct {
	policy    *StreamPolicy
	parent    context.Context
	ctx       context.Context
	cancel    context.CancelCauseFunc
	deadline  time.Time
	onConfirm func(endedRefusal string)

	confirmOnce sync.Once
	lastRead    atomic.Int64
	opened      chan struct{}
	done        chan struct{}
}

// Connect starts a connection attempt and draws its planned close. onConfirm,
// when not nil, is called once if the stream is confirmed live, with the
// cause of the quarantine that confirmation ended or "". It runs on the
// goroutine that reads the source. Every connection must be finished with End.
func (p *StreamPolicy) Connect(ctx context.Context, onConfirm func(endedRefusal string)) *StreamConnection {
	plannedIn := StreamPlannedCloseMin + time.Duration(p.cfg.Rand()*float64(StreamPlannedCloseMax-StreamPlannedCloseMin))
	conn := &StreamConnection{
		policy:    p,
		parent:    ctx,
		deadline:  p.cfg.Now().Add(plannedIn),
		onConfirm: onConfirm,
		opened:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	conn.ctx, conn.cancel = context.WithCancelCause(ctx)
	planned, release := p.cfg.Timer(plannedIn)
	go conn.watch(planned, release)
	return conn
}

// watch closes the connection at its planned close, or when it has been open
// and silent for StreamSilenceLimit.
func (c *StreamConnection) watch(planned <-chan time.Time, releasePlanned func()) {
	defer close(c.done)
	defer releasePlanned()
	opened := c.opened
	var silence <-chan time.Time
	releaseSilence := func() {}
	defer func() { releaseSilence() }()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-planned:
			c.cancel(errStreamPlannedClose)
			return
		case <-opened:
			opened = nil
			silence, releaseSilence = c.policy.cfg.Timer(StreamSilenceLimit)
		case <-silence:
			idle := c.policy.cfg.Now().Sub(time.Unix(0, c.lastRead.Load()))
			if idle >= StreamSilenceLimit {
				c.cancel(ErrStreamSilent)
				return
			}
			silence, releaseSilence = c.policy.cfg.Timer(StreamSilenceLimit - idle)
		}
	}
}

// Context is the connection's context. It is done at the planned close, on
// silence, on Reopen, and when the stream's owner stops it.
func (c *StreamConnection) Context() context.Context { return c.ctx }

// Open makes the connection. A quarantined stream first reads its credentials
// again; if they cannot be read the attempt fails without a request (§4).
// The stream is asked to end at the planned close.
func (c *StreamConnection) Open() (awid.EventSource, error) {
	p := c.policy
	p.mu.Lock()
	open, reload := p.open, p.refused && p.reload != nil
	p.mu.Unlock()
	if reload {
		reloaded, err := p.reload()
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.open = reloaded
		p.mu.Unlock()
		open = reloaded
	}
	source, err := open(c.ctx, c.deadline)
	if err != nil {
		return nil, err
	}
	c.read()
	if activity, ok := source.(streamActivitySource); ok {
		activity.OnRead(c.read)
		activity.OnComment(c.confirm)
	}
	close(c.opened)
	return source, nil
}

// read records that the connection delivered bytes. Every byte counts (§6).
func (c *StreamConnection) read() {
	c.lastRead.Store(c.policy.cfg.Now().UnixNano())
}

// confirm records the stream as live: its first event or heartbeat has been
// read (§3).
func (c *StreamConnection) confirm() {
	c.confirmOnce.Do(func() {
		ended := c.policy.confirmed()
		if c.onConfirm != nil {
			c.onConfirm(ended)
		}
	})
}

// Event records that the source delivered an event. The client calls it for
// every event Next returns.
func (c *StreamConnection) Event() {
	c.read()
	c.confirm()
}

// Reopen closes the connection because its client wants a fresh one. It ends
// as a planned close: reconnect at once, not an outage.
func (c *StreamConnection) Reopen() {
	c.cancel(errStreamPlannedClose)
}

// End finishes the attempt and classifies it. err is what Open returned, or
// what ended the reading of the source.
func (c *StreamConnection) End(err error) StreamEnd {
	stopped := c.parent.Err() != nil
	closedBy := context.Cause(c.ctx)
	c.cancel(errStreamEnded)
	<-c.done
	switch {
	case stopped:
		return StreamEnd{Kind: StreamEndStopped, Err: err}
	case errors.Is(closedBy, errStreamPlannedClose):
		return StreamEnd{Kind: StreamEndPlannedClose}
	case errors.Is(closedBy, ErrStreamSilent):
		return c.policy.failed(StreamEndTransient, "silence", ErrStreamSilent)
	}
	// The deadline travels to the server as whole seconds, so a server that
	// closes at the deadline it was asked for can do so up to a second before
	// this connection's own timer. That end is the planned close.
	if errors.Is(err, io.EOF) && !c.policy.cfg.Now().Before(c.deadline.Truncate(time.Second)) {
		return StreamEnd{Kind: StreamEndPlannedClose}
	}
	kind, cause := ClassifyStreamFailure(err)
	return c.policy.failed(kind, cause, err)
}
