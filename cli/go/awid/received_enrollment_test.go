package awid

import (
	"context"
	"encoding/json"
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

func TestReceivedAddressIDTreeReadsTheSenderRegistryAndBindsTheFreshKey(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	for _, tc := range []struct {
		name, addressID, keyID, key, tree, state string
		status                                   int
	}{
		{"enrolled", "did:aw:sender", "did:aw:sender", "did:key:sender", `{"enrolled":true,"domain":"native.byot.example.com"}`, "enrolled", 200},
		{"not-enrolled", "did:aw:sender", "did:aw:sender", "did:key:sender", `{"enrolled":false}`, "not_enrolled", 200},
		{"missing", "did:aw:sender", "did:aw:sender", "did:key:sender", ``, "unknown", 200},
		{"malformed", "did:aw:sender", "did:aw:sender", "did:key:sender", `{"enrolled":"false"}`, "malformed", 200},
		{"wrong-key-id", "did:aw:sender", "did:aw:other", "did:key:sender", `{"enrolled":false}`, "unknown", 200},
		{"wrong-key", "did:aw:sender", "did:aw:sender", "did:key:other", `{"enrolled":false}`, "unknown", 200},
		{"wrong-address-id", "did:aw:other", "did:aw:sender", "did:key:sender", `{"enrolled":false}`, "unknown", 200},
		{"key-outage", "did:aw:sender", "did:aw:sender", "did:key:sender", ``, "unknown", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyReads := 0
			registry := NewRegistryResolver(&http.Client{Transport: receivedEnrollmentTransport(func(request *http.Request) (*http.Response, error) {
				if request.URL.Scheme != "http" || request.URL.Host != "127.0.0.1:1" || request.Header.Get("Authorization") != "" || request.Header.Get("X-AWID-Service-Token") != "" {
					t.Fatalf("wrong registry or credential transfer: %s", request.URL)
				}
				status := 200
				var body string
				switch request.URL.Path {
				case "/v1/namespaces/signup-owner.example.com/addresses/child":
					body = `{"domain":"signup-owner.example.com","name":"child","did_aw":"` + tc.addressID + `","current_did_key":"did:key:sender"}`
				case "/v1/did/did:aw:sender/key":
					keyReads++
					status = tc.status
					payload := map[string]any{"did_aw": tc.keyID, "current_did_key": tc.key}
					if tc.tree != "" {
						var tree any
						if err := json.Unmarshal([]byte(tc.tree), &tree); err != nil {
							t.Fatal(err)
						}
						payload["id_tree"] = tree
					}
					encoded, _ := json.Marshal(payload)
					body = string(encoded)
				default:
					t.Fatalf("unexpected request %s", request.URL)
				}
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}, staticTXTResolver{})
			if err := registry.SetIdentityRegistryURL("https://home.registry.test", "observer.example.com"); err != nil {
				t.Fatal(err)
			}
			// Ordinary sender verification has already selected this address's
			// foreign authority. Reuse that cached admission without real DNS.
			registry.storeRegistryCache("signup-owner.example.com", DomainAuthority{RegistryURL: "http://127.0.0.1:1"}, registryDiscoveryTTL)
			client := &Client{resolver: &ChainResolver{Registry: registry}}
			for range 2 {
				got := client.ReceivedAddressIDTreeEnrollment(t.Context(), "signup-owner.example.com/child", "did:aw:sender", "did:key:sender")
				if got.State != tc.state || (tc.state == "enrolled" && (got.Domain == nil || *got.Domain != "native.byot.example.com")) {
					t.Fatalf("got %+v, want %s", got, tc.state)
				}
			}
			wantReads := 2
			if tc.name == "wrong-address-id" {
				wantReads = 0
			}
			if tc.status == 503 && keyReads >= wantReads {
				return // The existing read client may retry a dependency refusal.
			}
			if keyReads != wantReads {
				t.Fatalf("key reads %d, want %d fresh reads", keyReads, wantReads)
			}
		})
	}
}
