package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A request envelope is signed by the same key that signs an agent's messages,
// and the server receives one with every request. It is not a message: it
// names no type, body or sender. Presented as the signed payload of mail or
// chat with any displayed text, it must not be reported as verified.
func TestSignedRequestEnvelopeIsNotAVerifiedMessage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "team-auth-envelope-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	type requestCase struct {
		Name             string `json:"name"`
		DIDKey           string `json:"did_key"`
		CanonicalPayload string `json:"canonical_payload"`
		SignatureB64     string `json:"signature_b64"`
	}
	var vector struct {
		Cases         []requestCase `json:"cases"`
		IdentityCases []requestCase `json:"identity_cases"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	cases := append(vector.Cases, vector.IdentityCases...)
	if len(cases) == 0 {
		t.Fatal("the vector holds no signed request envelope")
	}
	const reader = "did:key:reader"
	for _, request := range cases {
		for _, kind := range []string{"mail", "chat"} {
			t.Run(request.Name+"/"+kind, func(t *testing.T) {
				outer := map[string]any{
					"message_id":     "message",
					"from_did":       request.DIDKey,
					"to_did":         reader,
					"subject":        "text the sender never wrote",
					"body":           "text the sender never wrote",
					"signed_payload": request.CanonicalPayload,
					"signature":      request.SignatureB64,
				}
				var status VerificationStatus
				if kind == "mail" {
					c, _ := New("http://unused.invalid")
					c.did = reader
					raw, _ := json.Marshal(outer)
					var m InboxMessage
					if err := json.Unmarshal(raw, &m); err != nil {
						t.Fatal(err)
					}
					out, err := c.normalizeInboxResponse(context.Background(), &InboxResponse{Messages: []InboxMessage{m}})
					if err != nil {
						t.Fatal(err)
					}
					status = out.Messages[0].VerificationStatus
				} else {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{outer}})
					}))
					defer server.Close()
					c, _ := New(server.URL)
					c.did = reader
					out, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "conversation"})
					if err != nil {
						t.Fatal(err)
					}
					status = out.Messages[0].VerificationStatus
				}
				if status != Failed {
					t.Fatalf("status=%s want=%s", status, Failed)
				}
			})
		}
	}
}
