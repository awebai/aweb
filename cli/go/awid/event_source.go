package awid

import "context"

// EventSource is the protocol-layer abstraction for receiving agent events.
// Implementations handle connection management and reconnection internally.
type EventSource interface {
	Next(ctx context.Context) (*AgentEvent, error)
	Close() error
}
