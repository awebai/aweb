package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStoredRouteSignedDisplay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	for _, kind := range []string{"mail", "chat"} {
		for _, side := range []string{"to"} {
			for _, mode := range []string{"signed", "unrelated", "unsigned", "swapped", "bad_signature", "tampered_body", "empty_sender", "null_recipient", "number_recipient", "null_stable", "number_stable", "absent_conversation", "empty_conversation", "null_conversation", "number_conversation", "changed_conversation", "changed_message"} {
				t.Run(kind+"/"+side+"/"+mode, func(t *testing.T) {
					env := &MessageEnvelope{Type: kind, FromDID: did, ToDID: "", FromStableID: "did:aw:sender", ToStableID: "did:aw:recipient", Body: "signed body", MessageID: "message", ConversationID: "conversation"}
					expected := VerificationStale
					outerDID := "did:aw:sender"
					if side == "to" {
						outerDID = "did:aw:recipient"
					}
					switch mode {
					case "unrelated":
						outerDID = "did:aw:unrelated"
						expected = Failed
					case "unsigned":
						if side == "from" {
							env.FromStableID = ""
						} else {
							env.ToStableID = ""
						}
						expected = Failed
					case "swapped":
						if side == "from" {
							outerDID = env.ToStableID
						} else {
							outerDID = env.FromStableID
						}
						expected = Failed
					case "bad_signature", "tampered_body":
						expected = Failed
					}
					payload := CanonicalJSON(env)
					signed := map[string]any{}
					_ = json.Unmarshal([]byte(payload), &signed)
					switch mode {
					case "empty_sender":
						signed["from_did"] = ""
					case "null_recipient":
						signed["to_did"] = nil
					case "number_recipient":
						signed["to_did"] = 7
					case "null_stable":
						signed["to_stable_id"] = nil
					case "number_stable":
						signed["to_stable_id"] = 7
					case "absent_conversation":
						delete(signed, "conversation_id")
					case "empty_conversation":
						signed["conversation_id"] = ""
					case "null_conversation":
						signed["conversation_id"] = nil
					case "number_conversation":
						signed["conversation_id"] = 7
					}
					bytes, _ := json.Marshal(signed)
					payload = string(bytes)
					sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, bytes))
					if mode != "signed" {
						expected = Failed
					}
					if kind == "mail" && mode == "unsigned" {
						expected = VerificationStale
					}
					if mode == "bad_signature" {
						sig = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
					}
					raw := map[string]any{"from_did": did, "to_did": did, "from_stable_id": "did:aw:sender", "to_stable_id": "did:aw:recipient", "message_id": env.MessageID, "body": env.Body, "conversation_id": env.ConversationID, "signed_payload": payload, "signature": sig}
					raw[side+"_did"] = outerDID
					if mode == "empty_sender" {
						raw["from_did"] = "did:aw:sender"
					}
					if mode == "changed_conversation" {
						raw["conversation_id"] = "changed"
					}
					if mode == "changed_message" {
						raw["message_id"] = "changed"
					}
					if mode == "tampered_body" {
						raw["body"] = "tampered"
					}
					var status VerificationStatus
					var got map[string]any
					if kind == "mail" {
						c, _ := New("http://unused.invalid")
						c.did = did
						c.stableID = "did:aw:recipient"
						data, _ := json.Marshal(raw)
						var m InboxMessage
						_ = json.Unmarshal(data, &m)
						out, err := c.normalizeInboxResponse(context.Background(), &InboxResponse{Messages: []InboxMessage{m}})
						if err != nil {
							t.Fatal(err)
						}
						status = out.Messages[0].VerificationStatus
						data, _ = json.Marshal(out.Messages[0])
						_ = json.Unmarshal(data, &got)
					} else {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{raw}})
						}))
						defer server.Close()
						c, _ := New(server.URL)
						c.stableID = "did:aw:recipient"
						out, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "conversation"})
						if err != nil {
							t.Fatal(err)
						}
						status = out.Messages[0].VerificationStatus
						data, _ := json.Marshal(out.Messages[0])
						_ = json.Unmarshal(data, &got)
					}
					if status != expected {
						t.Fatalf("status=%s want=%s", status, expected)
					}
					if mode != "signed" && mode != "bad_signature" && got[side+"_did"] != outerDID {
						t.Fatalf("mismatched raw DID lost: %v", got)
					}
				})
			}
		}
	}
}
