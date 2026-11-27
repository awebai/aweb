package eventstream

import (
	"context"
	"errors"
	"io"
	"sync"

	awid "github.com/awebai/aw/awid"
)

// fakeEventSource delivers pre-loaded events, then returns io.EOF.
type fakeEventSource struct {
	mu     sync.Mutex
	events []awid.AgentEvent
	index  int
	closed bool
}

func newFakeEventSource(events ...awid.AgentEvent) *fakeEventSource {
	return &fakeEventSource{events: events}
}

func (f *fakeEventSource) Next(_ context.Context) (*awid.AgentEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, errors.New("closed")
	}
	if f.index >= len(f.events) {
		return nil, io.EOF
	}
	ev := f.events[f.index]
	f.index++
	return &ev, nil
}

func (f *fakeEventSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// blockingEventSource delivers nothing until its context ends.
type blockingEventSource struct{}

func (blockingEventSource) Next(ctx context.Context) (*awid.AgentEvent, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingEventSource) Close() error { return nil }
