package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpawnAcceptRetryKeepsTheSignedRequest(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	request := &SpawnAcceptInviteRequest{
		Token: "aw_inv_fixture", DID: did,
		IDTree: &IDTreeCreationRequest{V: 1, RequestID: "20000000-0000-4000-8000-000000000001"},
	}
	exactBody, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		retryAfter  string
		wantPosts   int32
		wantSuccess bool
		stallReplay bool
	}{
		{"retry-after", "1", 2, true, false},
		{"retry-after-exceeds-budget", "60", 1, false, false},
		{"replay-request-deadline", "", 2, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			var refusedAt atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != spawnAcceptInvitePath {
					http.NotFound(w, r)
					return
				}
				raw, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(exactBody, raw) {
					t.Error("replay changed the serialized request, including its request ID")
				}
				auth := strings.Fields(r.Header.Get("Authorization"))
				if len(auth) != 3 || auth[0] != "DIDKey" || auth[1] != did {
					t.Error("replay changed the signer")
				} else {
					signature, err := base64.RawStdEncoding.DecodeString(auth[2])
					payload := onboardingDIDKeySignPayload(r.Method, r.URL.Path, r.Header.Get("X-AWEB-Timestamp"), raw)
					if err != nil || !ed25519.Verify(pub, payload, signature) {
						t.Error("acceptance signature is invalid")
					}
				}
				if posts.Add(1) == 1 {
					if tc.retryAfter != "" {
						w.Header().Set("Retry-After", tc.retryAfter)
					}
					refusedAt.Store(time.Now().UnixNano())
					w.WriteHeader(http.StatusConflict)
					fmt.Fprint(w, `{"detail":{"code":"registry_operation_in_progress","message":"Repeat the same request shortly."}}`)
					return
				}
				if tc.retryAfter == "1" && time.Since(time.Unix(0, refusedAt.Load())) < time.Second {
					t.Error("second request came before Retry-After")
				}
				if tc.stallReplay {
					<-r.Context().Done()
					return
				}
				fmt.Fprint(w, `{"team_id":"shared:aweb.ai"}`)
			}))
			defer server.Close()
			client, err := NewWithIdentity(server.URL, key, did)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			started := time.Now()
			response, err := client.AcceptSpawnInvite(ctx, request)
			if tc.wantSuccess {
				if err != nil || response.TeamID != "shared:aweb.ai" {
					t.Errorf("replay result = %v, %v", response, err)
				}
			} else if RefusalCode(err) != "registry_operation_in_progress" {
				t.Errorf("want last typed overlap refusal, got %v", err)
			}
			if posts.Load() != tc.wantPosts {
				t.Errorf("accept POSTs = %d, want %d", posts.Load(), tc.wantPosts)
			}
			if elapsed := time.Since(started); elapsed > 6*time.Second {
				t.Errorf("accept replay exceeded five-second budget: %v", elapsed)
			}
		})
	}
}
