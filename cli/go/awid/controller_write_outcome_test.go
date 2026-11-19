package awid

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A controller write is reported as possibly applied only when the registry
// received all of it and gave no answer. A refusal the registry answered, a
// write that never reached the registry, and a replay-safe write keep their
// own errors.
func TestControllerWriteIsPossiblyAppliedOnlyWhenTheRegistryReceivedItAndDidNotAnswer(t *testing.T) {
	_, controllerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	dropAfterReading := func(calls *atomic.Int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			_, _ = io.ReadAll(r.Body)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}

	t.Run("lost answer", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(dropAfterReading(&calls))
		t.Cleanup(server.Close)
		client := NewAWIDRegistryClient(server.Client(), nil)
		routeUntrustedRegistriesToInjectedClient(client)
		err := client.DeleteTeam(context.Background(), server.URL, "acme.com", "ops", controllerKey, "")
		var unknown *OutcomeUnknownError
		if !errors.As(err, &unknown) {
			t.Fatalf("err=%v, want OutcomeUnknownError", err)
		}
		want := "The registry may have applied this team delete; check its state (for example `aw id team members`) before retrying."
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err=%q does not say %q", err, want)
		}
		if calls.Load() != 1 {
			t.Fatalf("calls=%d, want the one write and no replay", calls.Load())
		}
	})

	t.Run("answered refusal", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"detail":"team has active certificates"}`)
		}))
		t.Cleanup(server.Close)
		client := NewAWIDRegistryClient(server.Client(), nil)
		routeUntrustedRegistriesToInjectedClient(client)
		err := client.DeleteTeam(context.Background(), server.URL, "acme.com", "ops", controllerKey, "")
		var refused *RegistryError
		var unknown *OutcomeUnknownError
		if !errors.As(err, &refused) || errors.As(err, &unknown) {
			t.Fatalf("err=%v, want the registry's refusal alone", err)
		}
	})

	t.Run("never reached the registry", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closedURL := "http://" + listener.Addr().String()
		_ = listener.Close()
		client := NewAWIDRegistryClient(&http.Client{}, nil)
		routeUntrustedRegistriesToInjectedClient(client)
		err = client.DeleteTeam(context.Background(), closedURL, "acme.com", "ops", controllerKey, "")
		var unknown *OutcomeUnknownError
		if err == nil || errors.As(err, &unknown) {
			t.Fatalf("err=%v, want the connection failure alone", err)
		}
	})

	t.Run("replay-safe write", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(dropAfterReading(&calls))
		t.Cleanup(server.Close)
		client := NewAWIDRegistryClient(server.Client(), nil)
		routeUntrustedRegistriesToInjectedClient(client)
		_, err := client.RegisterAddressAt(context.Background(), server.URL, "acme.com", "alice", "did:aw:test", "did:key:test", controllerKey)
		var unknown *OutcomeUnknownError
		if err == nil || errors.As(err, &unknown) {
			t.Fatalf("err=%v, want the transport failure after its replays", err)
		}
		if calls.Load() < 2 {
			t.Fatalf("calls=%d, want the replay-safe write replayed", calls.Load())
		}
	})
}
