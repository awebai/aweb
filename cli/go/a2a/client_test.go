package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRPCCredentialsDoNotFollowRedirectsToAnotherOrigin(t *testing.T) {
	var received atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Store(true)
		if _, err := w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`)); err != nil {
			t.Error(err)
		}
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	for _, credential := range []Credential{{APIKey: "secret"}, {BearerToken: "secret"}, {TaskToken: "secret"}} {
		err := (&Client{}).Call(context.Background(), origin.URL, MethodGetTask, map[string]string{"id": "task"}, credential, nil)
		if err == nil || !strings.Contains(err.Error(), "same origin") || received.Load() {
			t.Fatalf("credential-bearing redirect escaped: destination called=%v err=%v", received.Load(), err)
		}
	}
}

func TestRPCCredentialsFollowSameOriginTLSRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		if r.Header.Get("X-A2A-API-Key") != "secret" {
			t.Error("same-origin redirect lost its scoped credential")
		}
		if _, err := w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	if err := (&Client{HTTPClient: server.Client()}).Call(context.Background(), server.URL+"/start", MethodGetTask, nil, Credential{APIKey: "secret"}, nil); err != nil {
		t.Fatal(err)
	}
}
