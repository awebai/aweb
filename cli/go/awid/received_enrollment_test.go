package awid

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type receivedEnrollmentTransport func(*http.Request) (*http.Response, error)

func (f receivedEnrollmentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReceivedIDTreeReusesTheSameKeySnapshotAndExpiresAt61Seconds(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	reads := 0
	registry := NewRegistryResolver(&http.Client{Transport: receivedEnrollmentTransport(func(request *http.Request) (*http.Response, error) {
		reads++
		if request.URL.String() != "http://127.0.0.1:1/v1/did/did:aw:sender/key" {
			t.Fatalf("unexpected lookup %s", request.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"did_aw":"did:aw:sender","current_did_key":"did:key:sender","id_tree":{"enrolled":false}}`))}, nil
	})}, nil)
	registry.Now = func() time.Time { return now }
	if err := registry.SetFallbackRegistryURL("http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	url, scoped, err := registry.receivedRegistry(context.Background(), "selected:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.resolveKeyFresh(context.Background(), url, "did:aw:sender", true); err != nil {
		t.Fatal(err)
	}
	c := &Client{resolver: &ChainResolver{Team: &TeamRosterResolver{TeamID: "selected:example.com"}, DeliveryTeamRegistry: registry}}
	for _, age := range []int{0, 60, 61} {
		now = time.Date(2026, 10, 30, 0, 0, age, 0, time.UTC)
		got := c.ReceivedIDTreeEnrollment(context.Background(), "did:aw:sender", "did:key:sender")
		want := "not_enrolled"
		if age == 61 {
			want = "unknown"
		}
		if got.State != want {
			t.Fatalf("age %d got %+v", age, got)
		}
	}
	if reads != 1 {
		t.Fatalf("enrollment must reuse the authenticated key snapshot; %d reads", reads)
	}
	now = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	if got := c.ReceivedIDTreeEnrollment(context.Background(), "did:aw:sender", "did:key:other"); got.State != "unknown" {
		t.Fatalf("wrong key got %+v", got)
	}
}
