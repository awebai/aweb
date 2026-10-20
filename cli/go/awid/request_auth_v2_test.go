package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Each request family must sign its final wire target, including the mount,
// percent encoding and raw query. The receiver verifies the actual signature.
func TestClientRequestFamiliesUseTargetBoundV2(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"certificate", "identity"} {
		for _, transport := range []string{"json", "events", "chat"} {
			t.Run(family+"/"+transport, func(t *testing.T) {
				received := make(chan error, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/health") {
						return
					}
					signed, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
					if err != nil || len(signed) == 0 {
						t.Error("missing v2 signed payload")
						received <- nil
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					hash := sha256.Sum256(body)
					expected := map[string]any{
						"v": 2, "aud": "http://" + r.Host, "method": r.Method,
						"path": r.RequestURI, "body_sha256": hex.EncodeToString(hash[:]),
						"timestamp": r.Header.Get("X-AWEB-Timestamp"),
					}
					if family == "certificate" {
						expected["team_id"] = "backend:acme.com"
					} else {
						expected["did_aw"] = "did:aw:test"
					}
					canonical, err := CanonicalJSONValue(expected)
					if err != nil || string(signed) != canonical {
						t.Errorf("signed=%s, want=%s (%v)", signed, canonical, err)
					}
					auth := strings.Fields(r.Header.Get("Authorization"))
					if len(auth) != 3 {
						t.Error("missing DIDKey auth")
					} else {
						sig, err := base64.RawStdEncoding.DecodeString(auth[2])
						if err != nil || !ed25519.Verify(pub, signed, sig) {
							t.Error("invalid signature")
						}
					}
					w.Header().Set("Content-Type", "text/event-stream")
					w.Write([]byte("{}"))
					received <- nil
				}))
				defer server.Close()
				var client *Client
				if family == "certificate" {
					client, err = NewWithCertificate(server.URL+"/mount", key, testTeamCertificate(t, key, "alice"))
				} else {
					client, err = NewWithIdentity(server.URL+"/mount", key, ComputeDIDKey(pub))
					client.SetStableID("did:aw:test")
				}
				if err != nil {
					t.Fatal(err)
				}
				switch transport {
				case "json":
					resp, e := client.DoRaw(context.Background(), "POST", "/v1/tasks/a%2Fb?q=x%2Fy&b=1&a=2", "application/json", json.RawMessage(`{"title":"<bound & unchanged>"}`))
					err = e
					if resp != nil {
						resp.Body.Close()
					}
				case "events":
					stream, e := client.EventStream(context.Background(), time.Now().Add(time.Second))
					err = e
					if stream != nil {
						stream.Close()
					}
				case "chat":
					after := time.Now()
					stream, e := client.ChatStream(context.Background(), "session/id", time.Now().Add(time.Second), &after)
					err = e
					if stream != nil {
						stream.Close()
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				<-received
			})
		}
	}
}

func TestRequestAuthPayloadVectors(t *testing.T) {
	// The certificate case is the existing operation-free public v2 vector.
	// The identity case uses its own required claim and the same binding rules.
	for _, vector := range []struct{ claim, value, expected string }{
		{"team_id", "engineering:example.com", `{"aud":"https://coordination.example.com","body_sha256":"6968ffb71df7a14c4ec20c9bb266013dc0d5ff280ab6740239fd2628d3eaab63","method":"POST","path":"/v1/tasks","team_id":"engineering:example.com","timestamp":"2026-06-12T10:00:00Z","v":2}`},
		{"did_aw", "did:aw:test", `{"aud":"https://coordination.example.com","body_sha256":"6968ffb71df7a14c4ec20c9bb266013dc0d5ff280ab6740239fd2628d3eaab63","did_aw":"did:aw:test","method":"POST","path":"/v1/tasks","timestamp":"2026-06-12T10:00:00Z","v":2}`},
	} {
		t.Run(vector.claim, func(t *testing.T) {
			target, _ := url.Parse("https://coordination.example.com/v1/tasks")
			payload, err := requestAuthPayload("POST", target, vector.claim, vector.value, "2026-06-12T10:00:00Z", []byte(`{"title":"prepare review"}`), nil)
			if err != nil || string(payload) != vector.expected {
				t.Fatalf("got %s (%v), want %s", payload, err, vector.expected)
			}
		})
	}
}

func TestSignRequestCredentialRefusesCallerAuthorityClaimsAndInvalidInputs(t *testing.T) {
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse("https://example.test/mount/a%2Fb?q=x%2Fy&b=2&a=1")
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"team_id", "did_aw"} {
		for _, field := range []string{"v", "aud", "method", "path", "body_sha256", "timestamp", "team_id", "did_aw"} {
			t.Run(claim+"/"+field, func(t *testing.T) {
				if _, _, _, err := SignRequestCredential(key, "POST", target, claim, "selected", "2026-06-12T10:00:00Z", []byte(`{}`), map[string]any{field: "caller-chosen"}); err == nil {
					t.Fatal("caller-supplied authority claim was signed")
				}
			})
		}
	}
	for _, invalidKey := range []ed25519.PrivateKey{nil, {1}, make([]byte, ed25519.SeedSize)} {
		if _, _, _, err := SignRequestCredential(invalidKey, "GET", target, "did_aw", "", "2026-06-12T10:00:00Z", nil, nil); err == nil {
			t.Fatal("invalid signing key accepted")
		}
	}
	if _, _, _, err := SignRequestCredential(key, "GET", nil, "did_aw", "", "2026-06-12T10:00:00Z", nil, nil); err == nil {
		t.Fatal("missing target accepted")
	}
	if _, _, _, err := SignRequestCredential(key, "GET", target, "operation", "rotate_key", "2026-06-12T10:00:00Z", nil, nil); err == nil {
		t.Fatal("non-identity claim accepted")
	}
}
