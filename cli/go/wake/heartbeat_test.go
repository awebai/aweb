package wake

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/wake/session"
)

type heartbeatInspectAnswer struct {
	present bool
	err     error
}

// Every tick must obtain a new answer. The next inspect is also a barrier:
// the previous tick has completed all its heartbeat requests.
type heartbeatSession struct {
	requests chan chan heartbeatInspectAnswer
}

func (s *heartbeatSession) Inspect(ctx context.Context, home string) (session.Inspection, error) {
	answer := make(chan heartbeatInspectAnswer, 1)
	select {
	case s.requests <- answer:
	case <-ctx.Done():
		return session.Inspection{}, ctx.Err()
	}
	select {
	case got := <-answer:
		return session.Inspection{Home: home, Present: got.present}, got.err
	case <-ctx.Done():
		return session.Inspection{}, ctx.Err()
	}
}
func (*heartbeatSession) Input(context.Context, string, string) error { return nil }

func TestPresenceHeartbeatUsesFreshInspectAndStopsOnDeregister(t *testing.T) {
	requests := make(chan string, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/agents/heartbeat" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		requests <- r.Header.Get("X-Test-Identity")
		w.WriteHeader(200)
	}))
	defer server.Close()
	inspect := &heartbeatSession{requests: make(chan chan heartbeatInspectAnswer)}
	store := tempStore(t)
	broker, _ := liveBroker(t, Config{Store: store, Session: inspect, HeartbeatInterval: 10 * time.Millisecond,
		Heartbeat: func(ctx context.Context, home, team string) error {
			req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/agents/heartbeat", nil)
			req.Header.Set("X-Test-Identity", home+"|"+team)
			resp, err := server.Client().Do(req)
			if err == nil {
				resp.Body.Close()
			}
			return err
		},
	})
	home := tempHome(t, "session")
	identity := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identity, "dev:example.com")
	if err := broker.Register(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	nextInspect := func() chan heartbeatInspectAnswer {
		t.Helper()
		select {
		case reply := <-inspect.requests:
			return reply
		case <-time.After(2 * time.Second):
			t.Fatal("no fresh heartbeat inspect")
			return nil
		}
	}
	expectBeat := func() {
		t.Helper()
		select {
		case got := <-requests:
			if got != identity+"|dev:example.com" {
				t.Fatalf("heartbeat identity=%s", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("present session did not heartbeat")
		}
	}
	noBeat := func() {
		t.Helper()
		select {
		case got := <-requests:
			t.Fatalf("heartbeat after absent/error: %s", got)
		default:
		}
	}
	nextInspect() <- heartbeatInspectAnswer{present: true}
	expectBeat()
	nextInspect() <- heartbeatInspectAnswer{present: false}
	pending := nextInspect()
	noBeat()
	pending <- heartbeatInspectAnswer{err: errors.New("inspect unavailable")}
	pending = nextInspect()
	noBeat()
	pending <- heartbeatInspectAnswer{present: true}
	expectBeat()
	runner, ok := broker.instanceRunner(home)
	if !ok {
		t.Fatal("missing runner")
	}
	pending = nextInspect() // Hold an inspect in flight while deregistering.
	if err := broker.Deregister(home); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.done:
	default:
		t.Fatal("deregister did not stop heartbeat runner")
	}
	noBeat()
}
