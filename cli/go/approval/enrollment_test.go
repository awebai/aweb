package approval

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
)

// Exercise the public transport and real HTTP proof/answer primitives against
// every frozen read-answer neighbor, without replacing the verifier's policy.
func TestEnrollmentTransportPreservesSharedAnswerDecisions(t *testing.T) {
	count := 0
	for _, vector := range cases(t, "issuer-service-enrollment") {
		if vector["phase"] != "answer" || vector["mode"] != "read" {
			continue
		}
		count++
		t.Run(vector["id"].(string), func(t *testing.T) {
			purpose := RequestPurpose(vector["kind"].(string))
			answer := decoded(t, vector["answer"].(string))
			intent := vector["intent"].(map[string]any)
			var requestBytes []byte
			if encoded, ok := vector["request_bytes"].(string); ok {
				requestBytes = decoded(t, encoded)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
			requester := map[string]any{"kind": "identity", "id": awid.ComputeStableID(key.Public().(ed25519.PublicKey)), "key": awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))}
			body := map[string]any{"version": 1, "intent": intent}
			wantBody, err := proof.Canonical(body)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1795040000, 0)
			var client *Client
			calls := 0
			peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != routes[purpose] || !bytes.Equal(raw, wantBody) {
					t.Errorf("changed enrollment target or packet")
				}
				if _, err := proof.CheckHTTP(r.Header.Get("Authorization"), raw, proof.HTTPInput{Requester: requester, Origin: client.Origin, Method: r.Method, Path: r.URL.Path, Purpose: string(purpose), Now: now.Unix()}); err != nil {
					t.Errorf("covering request: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(int(num(vector["response_status"])))
				if _, err := w.Write(answer); err != nil {
					t.Error(err)
				}
			}))
			defer peer.Close()
			client = &Client{Origin: peer.URL, Key: key, Requester: requester, HTTP: peer.Client(), Now: func() time.Time { return now }}
			got, err := client.ExchangeEnrollment(t.Context(), EnrollmentExchangeInput{Purpose: purpose, Body: body, Intent: intent, RequestBytes: requestBytes})
			if calls != 1 {
				t.Fatalf("sent %d requests, want one", calls)
			}
			if vector["accept"] == true {
				if err != nil {
					t.Fatal(err)
				}
				canonical, err := proof.Canonical(got)
				if err != nil || !bytes.Equal(canonical, answer) {
					t.Fatalf("checked answer changed: %v", err)
				}
			} else {
				var refusal *proof.RefusalError
				if !errors.As(err, &refusal) || string(refusal.Code) != vector["expected_error"] || got != nil {
					t.Fatalf("answer refusal %v, want %v", err, vector["expected_error"])
				}
			}
		})
	}
	if count != 14 {
		t.Fatalf("covered %d frozen answer rows, want 14", count)
	}
}
