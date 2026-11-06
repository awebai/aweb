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
	joined := filepath.Join(tempHome(t, "joined"), ".aw")
	writeWakeTestTeamState(t, joined, "ops:example.com")
	poll := filepath.Join(tempHome(t, "poll-only"), ".aw")
	writeWakeTestTeamState(t, poll, "team:poll")
	if err := broker.Register(Registration{Home: home, PresenceIdentities: []PresenceIdentity{{IdentityHome: poll}}, RuntimeDelivery: RuntimeDeliveryExternalSession, ReceiveIdentities: []ReceiveIdentity{
		{IdentityHome: identity, TeamID: "dev:example.com", DeliveryOwner: ReceiveOwnerSessionHints, Controls: true},
		{IdentityHome: joined, TeamID: "ops:example.com", DeliveryOwner: ReceiveOwnerSessionHints},
	}}); err != nil {
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
		want := []string{identity + "|dev:example.com", joined + "|ops:example.com", poll + "|team:poll"}
		for _, expected := range want {
			select {
			case got := <-requests:
				if got != expected {
					t.Fatalf("heartbeat identity=%s want %s in receive-then-presence order", got, expected)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("present session did not heartbeat each identity")
			}
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
	pending <- heartbeatInspectAnswer{present: true, err: errors.New("inspect unavailable")}
	pending = nextInspect()
	noBeat()
	pending <- heartbeatInspectAnswer{present: true}
	expectBeat()
	runner, ok := broker.instanceRunner(home)
	if !ok {
		t.Fatal("missing runner")
	}
	pending = nextInspect() // Hold an inspect in flight while deregistering.
	if _, err := broker.Deregister(home); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.done:
	default:
		t.Fatal("deregister did not stop heartbeat runner")
	}
	noBeat()
}

func TestPresenceHeartbeatAtStartDoesNotWaitForTicker(t *testing.T) {
	arrived := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/agents/heartbeat" {
			t.Errorf("unexpected heartbeat %s %s", r.Method, r.URL.Path)
		}
		arrived <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	inspect := session.NewFake(session.Inspection{Present: true})
	broker, _ := liveBroker(t, Config{Store: tempStore(t), Session: inspect, HeartbeatInterval: time.Hour,
		Heartbeat: func(ctx context.Context, home, team string) error {
			req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/agents/heartbeat", nil)
			res, err := server.Client().Do(req)
			if err == nil {
				res.Body.Close()
			}
			return err
		},
	})
	home := tempHome(t, "startup")
	identity := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identity, "dev:example.com")
	if err := broker.Register(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("startup heartbeat waited for ticker")
	}
	if got := inspect.Inspects(); len(got) != 1 || got[0] != home {
		t.Fatalf("startup inspect=%v", got)
	}
}

func TestPresenceHeartbeatNativeChannelWithPresenceOnly(t *testing.T) {
	reg := presenceRegistration(t)
	reg.RuntimeDelivery = RuntimeDeliveryNativeChannel
	reg.Delivery = RuntimeDeliveryNativeChannel
	if len(reg.ReceiveIdentities) != 0 {
		t.Fatal("fixture must have no receive identities")
	}
	want := reg.PresenceIdentities[0].IdentityHome + "|team:poll"
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/heartbeat" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		requests <- r.Header.Get("X-Test-Identity")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	inspect := session.NewFake(session.Inspection{Present: true})
	broker, _ := liveBroker(t, Config{
		Store: tempStore(t), Session: inspect, HeartbeatInterval: time.Hour,
		Heartbeat: func(ctx context.Context, home, team string) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/agents/heartbeat", nil)
			if err != nil {
				return err
			}
			req.Header.Set("X-Test-Identity", home+"|"+team)
			resp, err := server.Client().Do(req)
			if err == nil {
				resp.Body.Close()
			}
			return err
		},
	})
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-requests:
		if got != want {
			t.Fatalf("native presence heartbeat=%q want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("native registration with only presence identities did not heartbeat")
	}
	if got := inspect.Inspects(); len(got) != 1 || got[0] != reg.Home {
		t.Fatalf("native presence inspect=%v", got)
	}
	if got := broker.Status(); len(got.Streams) != 0 || len(got.Instances) != 1 || len(got.Instances[0].ReceiveIdentities) != 0 {
		t.Fatalf("presence-only registration acquired receive state: %+v", got)
	}
}
