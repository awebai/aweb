package aweb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionLease404RequiresServer12628(t *testing.T) {
	tests := []struct {
		name       string
		wantMethod string
		wantPath   string
		invoke     func(context.Context, *Client) error
	}{
		{
			name:       "status",
			wantMethod: http.MethodGet,
			wantPath:   "/v1/session-leases",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.SessionLeaseGet(ctx)
				return err
			},
		},
		{
			name:       "acquire",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/session-leases",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.SessionLeaseAcquire(ctx, &SessionLeaseRequest{})
				return err
			},
		},
		{
			name:       "renew",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/session-leases/renew",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.SessionLeaseRenew(ctx, &SessionLeaseRequest{})
				return err
			},
		},
		{
			name:       "release",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/session-leases/release",
			invoke: func(ctx context.Context, client *Client) error {
				return client.SessionLeaseRelease(ctx, &SessionLeaseReleaseRequest{})
			},
		},
		{
			name:       "takeover",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/session-leases/takeover",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.SessionLeaseTakeover(ctx, &SessionLeaseTakeoverRequest{})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod, gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				http.Error(w, "route absent", http.StatusNotFound)
			}))
			t.Cleanup(server.Close)

			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = tt.invoke(context.Background(), client)
			if err == nil || !strings.Contains(err.Error(), "session leases require aweb server 1.26.28 or later") {
				t.Fatalf("error=%v, want minimum-server diagnostic", err)
			}
			if gotMethod != tt.wantMethod || gotPath != tt.wantPath {
				t.Fatalf("request=(%s %s), want (%s %s)", gotMethod, gotPath, tt.wantMethod, tt.wantPath)
			}
		})
	}
}

func TestSessionLeaseNon404PreservesOriginalError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "lease backend unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SessionLeaseGet(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lease backend unavailable") {
		t.Fatalf("error=%v, want original backend error", err)
	}
	if strings.Contains(err.Error(), "requires aweb server") {
		t.Fatalf("non-404 error was rewritten as a compatibility diagnostic: %v", err)
	}
}
