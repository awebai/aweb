package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A short HTTP body is a transport failure, not a complete OAuth refusal or
// successful response. Exercise the real HTTP reader rather than a fake client.
func TestCLIAuthRetainsIncompleteResponseErrors(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(status)
				if _, err := w.Write([]byte(`{"error":"expired"}`)); err != nil {
					t.Errorf("write short response: %v", err)
				}
			}))
			defer server.Close()
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = doCLIAuthJSON(req, nil, server.URL)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("short HTTP %d response discarded its read failure: %v", status, err)
			}
			if status != http.StatusOK {
				var statusErr *cliAuthHTTPStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != status {
					t.Fatalf("HTTP status lost with the read error: %v", err)
				}
			}
		})
	}
}
