package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInteractiveHumanClientSignsRequestAndMailWithoutExportingKey(t *testing.T) {
	key := testHumanKey()
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	store := installedHumanKey(t)
	var prompts []string
	signer := func(payload []byte, description string) (string, []byte, error) {
		return HumanSigner(store, testHumanID, description, func(text string) ([]byte, error) {
			prompts = append(prompts, text)
			return []byte("correct horse"), nil
		})(payload)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 3 || parts[1] != did {
			t.Errorf("auth=%q", r.Header.Get("Authorization"))
			return
		}
		payload, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		sig, _ := base64.RawStdEncoding.DecodeString(parts[2])
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, sig) {
			t.Error("invalid request signature")
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, err := NewWithInteractiveSigner(srv.URL, did, nil, signer)
	if err != nil {
		t.Fatal(err)
	}
	c.SetStableID(testHumanID)
	env := &MessageEnvelope{Type: "mail", To: "bob", Subject: "Review", Body: "Please review", ConversationID: "conversation"}
	fields, err := c.signEnvelope(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.RawStdEncoding.DecodeString(fields.Signature)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(fields.SignedPayload), sig) || fields.FromDID != did {
		t.Fatal("invalid mail attribution")
	}
	resp, err := c.DoRaw(context.Background(), "POST", "/v1/messages", "application/json", map[string]string{"body": "Please review"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if c.SigningKey() != nil {
		t.Fatal("interactive client retains a private key")
	}
	if len(prompts) != 2 {
		t.Fatalf("prompts=%d, want exactly 2", len(prompts))
	}
	if !strings.Contains(prompts[0], "bob") || !strings.Contains(prompts[0], "Review") || !strings.Contains(prompts[0], "sha256") {
		t.Fatalf("unrecognizable prompt: %s", prompts[0])
	}
}

func TestInteractiveClientRefusesWrongSignerAndChat(t *testing.T) {
	key := testHumanKey()
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	calls := 0
	c, err := NewWithInteractiveSigner("https://example.invalid", did, nil, func(p []byte, d string) (string, []byte, error) {
		calls++
		return "did:key:wrong", ed25519.Sign(key, p), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.signEnvelope(context.Background(), &MessageEnvelope{Type: "mail", To: "bob"})
	if err == nil {
		t.Fatal("wrong signer accepted")
	}
	calls = 0
	_, err = c.signEnvelope(context.Background(), &MessageEnvelope{Type: "chat", To: "bob"})
	if err == nil || calls != 0 {
		t.Fatalf("human chat err=%v calls=%d", err, calls)
	}
}
