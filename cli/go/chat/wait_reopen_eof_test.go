package chat

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A reopen that fails, even with a clean EOF, is reported as an error: the
// wait has not run out, so calling it a timeout would hide the failure.
func TestWaitReopenThatEndsAtOnceIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"messages":[]}`)
	}))
	defer server.Close()
	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	opener := func(context.Context, string, time.Time, *time.Time, int64) (*awid.SSEStream, error) {
		calls++
		if calls == 1 {
			return awid.NewSSEStream(io.NopCloser(strings.NewReader(": capped\n\n"))), nil
		}
		return nil, io.EOF
	}
	began := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := waitForMessage(ctx, client, opener, "s1", nil, "alice", 5, nil, nil, func(Event) (bool, bool) { return true, false })
	if err == nil {
		t.Fatalf("reconnect failed with EOF after %d opens, but returned status=%s nil error after %s (local wait is 5s)", calls, result.Status, time.Since(began))
	}
	if !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "reconnecting to SSE") {
		t.Fatalf("err=%v, want the reconnect failure wrapping io.EOF", err)
	}
}
