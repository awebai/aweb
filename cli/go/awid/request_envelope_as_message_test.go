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

type displayBindingVector struct {
	RequiredClaims map[string][]string `json:"required_claims"`
	SignerShapes   []struct {
		Name   string   `json:"name"`
		Kind   string   `json:"kind"`
		Claims []string `json:"claims"`
	} `json:"signer_shapes"`
}

func loadDisplayBindingVector(t *testing.T) displayBindingVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "message-display-binding-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector displayBindingVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.SignerShapes) == 0 || len(vector.RequiredClaims["mail"]) == 0 || len(vector.RequiredClaims["chat"]) == 0 {
		t.Fatal("the vector holds no signer shape or no required claim")
	}
	return vector
}

// signerShapeMatchesDisplay reports whether a reader accepts the displayed
// fields of a message against a signed payload that carries the given claims,
// each displayed field being the signed one.
func signerShapeMatchesDisplay(kind string, claims []string, without string) bool {
	const sender, reader = "did:key:sender", "did:key:reader"
	value := map[string]string{
		"type": kind, "from_did": sender, "to_did": reader,
		"from_stable_id": "did:aw:sender", "to_stable_id": "did:aw:reader",
	}
	signed := map[string]string{}
	for _, name := range claims {
		if name == without {
			continue
		}
		if v, ok := value[name]; ok {
			signed[name] = v
		} else {
			signed[name] = name
		}
	}
	payload, _ := json.Marshal(signed)
	displayed := map[string]string{
		"type": kind, "body": "body", "message_id": "message_id",
		"conversation_id": signed["conversation_id"], "from_did": sender, "to_did": reader,
	}
	if kind == "mail" {
		displayed["subject"] = "subject"
		return (&Client{did: reader}).signedMailDisplayMatches(string(payload), displayed, false)
	}
	return signedDisplayMatches(string(payload), displayed)
}

// Every payload shape a released signer produces carries the required claims,
// so requiring them refuses no genuine message.
func TestEveryReleasedSignerShapeMatchesItsDisplay(t *testing.T) {
	for _, shape := range loadDisplayBindingVector(t).SignerShapes {
		t.Run(shape.Name, func(t *testing.T) {
			if !signerShapeMatchesDisplay(shape.Kind, shape.Claims, "") {
				t.Fatal("a released signer's payload was refused")
			}
		})
	}
}

// A payload that lacks a required claim does not say what the reader is shown,
// whichever signer shape it otherwise has.
func TestSignedPayloadWithoutARequiredClaimDoesNotMatchItsDisplay(t *testing.T) {
	vector := loadDisplayBindingVector(t)
	for _, shape := range vector.SignerShapes {
		for _, claim := range vector.RequiredClaims[shape.Kind] {
			t.Run(shape.Name+"/"+claim, func(t *testing.T) {
				if signerShapeMatchesDisplay(shape.Kind, shape.Claims, claim) {
					t.Fatalf("a payload without %s was accepted", claim)
				}
			})
		}
	}
}
