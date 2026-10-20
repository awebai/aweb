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
