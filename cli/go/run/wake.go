package run

import (
	"context"
	"time"

	awid "github.com/awebai/aw/awid"
)

// EventStreamOpener opens a single SSE connection, asking the server to close
// it at deadline. A StreamPolicy calls it once per connection attempt.
type EventStreamOpener func(ctx context.Context, deadline time.Time) (awid.EventSource, error)

// NewEventStreamOpener returns an opener that connects to the given client's
// event stream endpoint.
func NewEventStreamOpener(client *awid.Client) EventStreamOpener {
	return func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
		return client.EventStream(ctx, deadline)
	}
}
