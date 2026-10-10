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

// The probe-57 reproducer, inverted: valid signed bytes must not authenticate
// a different displayed body or message ID. No network or identity state.
func TestProbe57DisplayBodyBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	env := &MessageEnvelope{FromDID: did, ToDID: did, Type: "mail", Body: "not the challenge", MessageID: "signed-id", ConversationID: "fresh-thread"}
	sig, err := SignMessage(key, env)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("http://unused.invalid")
	if err != nil {
		t.Fatal(err)
	}
	c.did = did
	got, err := c.normalizeInboxResponse(context.Background(), &InboxResponse{Messages: []InboxMessage{{MessageID: "outer-id", ConversationID: "fresh-thread", FromDID: did, ToDID: did, Body: "nonce only in unsigned display body", SignedPayload: CanonicalJSON(env), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	m := got.Messages[0]
	if m.VerificationStatus != Failed || m.Body != "nonce only in unsigned display body" || m.MessageID != "outer-id" {
		t.Fatalf("unsigned display must fail and remain observable: %+v", m)
	}
}

func TestSignedDisplayBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	for _, kind := range []string{"mail", "chat"} {
		fields := []string{"body", "message_id", "conversation_id", "from_did", "to_did"}
		if kind == "mail" {
			fields = append(fields, "subject")
		}
		for _, field := range fields {
			for _, mode := range []string{"matching", "tampered", "absent", "empty_match", "empty_mismatch", "null"} {
				t.Run(kind+"/"+field+"/"+mode, func(t *testing.T) {
					signed := map[string]any{"type": kind, "body": "body", "subject": "subject", "message_id": "message", "conversation_id": "conversation", "from_did": did, "to_did": did}
					outer := map[string]any{}
					for k, v := range signed {
						outer[k] = v
					}
					want := Verified
					switch mode {
					case "tampered":
						outer[field] = "tampered"
						want = Failed
					case "absent":
						delete(signed, field)
						if field == "conversation_id" {
							want = VerifiedLegacy
						}
					case "empty_match":
						signed[field] = ""
						outer[field] = ""
						if field == "from_did" {
							want = Unverified
						}
					case "empty_mismatch":
						signed[field] = ""
						want = Failed
						if kind == "mail" && field == "to_did" {
							// Empty legacy recipient claims may project only this
							// authenticated mail reader's own identity.
							want = Verified
						}
					case "null":
						signed[field] = nil
						want = Failed
					}
					payload, _ := json.Marshal(signed)
					outer["signed_payload"] = string(payload)
					outer["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
					var status VerificationStatus
					var returned map[string]any
					if kind == "mail" {
						c, _ := New("http://unused.invalid")
						c.did = did
						data, _ := json.Marshal(outer)
						var m InboxMessage
						if err := json.Unmarshal(data, &m); err != nil {
							t.Fatal(err)
						}
						out, err := c.normalizeInboxResponse(context.Background(), &InboxResponse{Messages: []InboxMessage{m}})
						if err != nil {
							t.Fatal(err)
						}
						status = out.Messages[0].VerificationStatus
						data, _ = json.Marshal(out.Messages[0])
						_ = json.Unmarshal(data, &returned)
					} else {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{outer}})
						}))
						defer server.Close()
						c, _ := New(server.URL)
						c.did = did
						out, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "conversation"})
						if err != nil {
							t.Fatal(err)
						}
						status = out.Messages[0].VerificationStatus
						data, _ := json.Marshal(out.Messages[0])
						_ = json.Unmarshal(data, &returned)
					}
					if status != want {
						t.Fatalf("status=%s want=%s", status, want)
					}
					if mode == "tampered" || mode == "empty_mismatch" || mode == "null" {
						for _, f := range fields {
							if returned[f] != outer[f] {
								t.Errorf("raw %s changed: got=%v want=%v", f, returned[f], outer[f])
							}
						}
					}
				})
			}
		}
	}
}

func TestSignedDisplayStableProjection(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	for _, kind := range []string{"mail", "chat"} {
		for _, side := range []string{"from", "to"} {
			for _, mode := range []string{"signed", "unrelated", "unsigned", "swapped", "bad_signature", "tampered_body"} {
				t.Run(kind+"/"+side+"/"+mode, func(t *testing.T) {
					env := &MessageEnvelope{Type: kind, FromDID: did, ToDID: did, FromStableID: "did:aw:sender", ToStableID: "did:aw:recipient", Body: "signed body", ConversationID: "conversation"}
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
					sig, _ := SignMessage(key, env)
					if mode == "bad_signature" {
						sig = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
					}
					raw := map[string]any{"from_did": did, "to_did": did, "from_stable_id": "did:aw:sender", "to_stable_id": "did:aw:recipient", "body": env.Body, "conversation_id": env.ConversationID, "signed_payload": payload, "signature": sig}
					raw[side+"_did"] = outerDID
					if mode == "tampered_body" {
						raw["body"] = "tampered"
					}
					var status VerificationStatus
					var got map[string]any
					if kind == "mail" {
						c, _ := New("http://unused.invalid")
						c.did = did
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
