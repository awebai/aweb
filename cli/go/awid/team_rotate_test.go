package awid

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A registry that never stops reporting more pages, each with a fresh cursor,
// must not keep the signed-records read going forever.
func TestListTeamSignedRecordsStopsAtThePageCap(t *testing.T) {
	var pages atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := pages.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"items": [], "has_more": true, "next_cursor": "c%d"}`, page)
	}))
	defer server.Close()
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewAWIDRegistryClient(server.Client(), nil).ListTeamSignedRecords(context.Background(), server.URL, "endless.example", "ops", 0, key)

	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("err = %v, want a truncated refusal", err)
	}
	if got := pages.Load(); got != signedRecordsPageCap {
		t.Fatalf("read %d pages, want the cap %d", got, signedRecordsPageCap)
	}
}
