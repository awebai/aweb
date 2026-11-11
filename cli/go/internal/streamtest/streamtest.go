// Package streamtest is test support for the clients of the event stream: an
// event source a test feeds one read at a time, and an opener that plays a
// script of attempts. With internal/manualclock they let a test walk a client
// through the event stream client policy without a server or real waiting.
package streamtest

import (
	"context"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
)

// Item is one thing a Source reads: a heartbeat comment, bytes that complete
// no line, an event, or the error that ends the stream.
type Item struct {
	Comment bool
	Partial bool
	Event   *awid.AgentEvent
	Err     error
}

// Source is an event source whose reads the test feeds one at a time. Like
// the real stream it reports every read, and every comment, to its observers
// from the goroutine that calls Next.
type Source struct {
	items     chan Item
	handled   chan struct{}
	onRead    func()
	onComment func()
	// delivered is true while the consumer holds an event Next returned.
	delivered bool
}

// NewSource returns a source that reads nothing until it is fed.
func NewSource() *Source {
	return &Source{items: make(chan Item), handled: make(chan struct{})}
}

func (s *Source) OnRead(f func())    { s.onRead = f }
func (s *Source) OnComment(f func()) { s.onComment = f }
func (s *Source) Close() error       { return nil }

func (s *Source) Next(ctx context.Context) (*awid.AgentEvent, error) {
	if s.delivered {
		// The consumer is back for more, so it has dealt with the event.
		s.delivered = false
		s.handled <- struct{}{}
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case item := <-s.items:
			if item.Err != nil {
				s.handled <- struct{}{}
				return nil, item.Err
			}
			if s.onRead != nil {
				s.onRead()
			}
			if item.Comment && s.onComment != nil {
				s.onComment()
			}
			if item.Event != nil {
				s.delivered = true
				return item.Event, nil
			}
			s.handled <- struct{}{}
		}
	}
}

// Feed hands the source one read and returns once the source has reported it
// and, for an event, once the consumer has dealt with it.
func (s *Source) Feed(item Item) {
	s.items <- item
	<-s.handled
}

// FeedEvent feeds one event.
func (s *Source) FeedEvent(event awid.AgentEvent) {
	s.Feed(Item{Event: &event})
}

// Attempt is one scripted attempt to open the stream.
type Attempt func(ctx context.Context, deadline time.Time) (awid.EventSource, error)

// Fails is an attempt that fails with err.
func Fails(err error) Attempt {
	return func(context.Context, time.Time) (awid.EventSource, error) { return nil, err }
}

// Opens is an attempt that opens source.
func Opens(source awid.EventSource) Attempt {
	return func(context.Context, time.Time) (awid.EventSource, error) { return source, nil }
}

// HTTPFailure is the error of an open the server answered with status.
func HTTPFailure(status int) error {
	return &awid.APIError{StatusCode: status}
}

// HTTPFailureRetryAfter is HTTPFailure with a Retry-After header.
func HTTPFailureRetryAfter(status int, retryAfter string) error {
	return &awid.APIError{StatusCode: status, RetryAfter: retryAfter}
}

// Opener plays its attempts in order and repeats the last one. It records
// when each attempt was made and the deadline it was given.
type Opener struct {
	now func() time.Time

	mu        sync.Mutex
	attempts  []Attempt
	openedAt  []time.Time
	deadlines []time.Time
}

// NewOpener returns an opener that reads the time of each attempt from now.
func NewOpener(now func() time.Time, attempts ...Attempt) *Opener {
	return &Opener{now: now, attempts: attempts}
}

// Open has the signature of run.EventStreamOpener.
func (o *Opener) Open(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
	o.mu.Lock()
	index := len(o.openedAt)
	if index >= len(o.attempts) {
		index = len(o.attempts) - 1
	}
	attempt := o.attempts[index]
	o.openedAt = append(o.openedAt, o.now())
	o.deadlines = append(o.deadlines, deadline)
	o.mu.Unlock()
	return attempt(ctx, deadline)
}

// Opens reports how many attempts have been made.
func (o *Opener) Opens() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.openedAt)
}

// OpenTimes reports when each attempt was made.
func (o *Opener) OpenTimes() []time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]time.Time(nil), o.openedAt...)
}

// LastDeadline reports the deadline the latest attempt was given.
func (o *Opener) LastDeadline() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.deadlines[len(o.deadlines)-1]
}

// ScaledTimer is a real timer that runs factor times faster than asked, for
// tests that reconnect over real connections and bound themselves in real
// time. It has the signature of run.StreamPolicyConfig.Timer.
func ScaledTimer(factor int) func(time.Duration) (<-chan time.Time, func()) {
	return func(d time.Duration) (<-chan time.Time, func()) {
		timer := time.NewTimer(d / time.Duration(factor))
		return timer.C, func() { timer.Stop() }
	}
}
