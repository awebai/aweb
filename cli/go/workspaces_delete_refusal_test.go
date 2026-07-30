package aweb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The sentinels are what callers branch on, and every existing check reaches them
// through a consumer. A rename or a reworded message would leave those consumers
// compiling and behaving differently with nothing naming the sentinel itself.
//
// The two 404s are told apart by the server's structured code, never by message
// text, so each case here supplies the code and leaves the prose free to change.
func TestWorkspaceDeleteDistinguishesTheTwo404s(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
		want error
	}{
		{"already deleted establishes the row is gone and its identity is not", "workspace_already_deleted", ErrWorkspaceAlreadyDeleted},
		{"not found establishes nothing", "workspace_not_found", ErrWorkspaceNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"detail": map[string]any{"code": tc.code, "recommended_next_step": "prose that may be reworded"},
				})
			}))
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.WorkspaceDelete(context.Background(), "ws-1")
			if resp != nil {
				t.Fatalf("a refusal must not yield a response callers can read as success: %+v", resp)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want errors.Is(..., %v)", err, tc.want)
			}
			// The two must never be interchangeable: one is an observation, the
			// other is an absence of one.
			other := ErrWorkspaceNotFound
			if tc.want == ErrWorkspaceNotFound {
				other = ErrWorkspaceAlreadyDeleted
			}
			if errors.Is(err, other) {
				t.Fatalf("err=%v matches BOTH sentinels; they carry different evidence", err)
			}
		})
	}
}

// A 404 the client cannot identify establishes nothing, so it must not be reported
// as either outcome. A server too old to carry the code lands here.
func TestWorkspaceDeleteRefusesToClassifyAnUnidentified404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.WorkspaceDelete(context.Background(), "ws-1")
	if resp != nil || err == nil {
		t.Fatalf("resp=%+v err=%v, want no response and an error", resp, err)
	}
	if errors.Is(err, ErrWorkspaceAlreadyDeleted) || errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatalf("an unidentifiable 404 was classified as a specific outcome: %v", err)
	}
}
