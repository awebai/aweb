package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSignedIdentityPostBindsOwnedBodyAndTargetAndRefusesRedirect(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	redirected := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer destination.Close()
	var received []byte
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var readErr error
		received, readErr = io.ReadAll(r.Body)
		if readErr != nil {
			t.Error(readErr)
		}
		headers = r.Header.Clone()
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/activate?selection=1")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"operation":"activate"}`)
	request, err := NewSignedIdentityPostRequest(context.Background(), SignedIdentityPost{
		DIDKey: ComputeDIDKey(pub), StableID: "did:aw:person", Target: target,
		Timestamp: "2026-11-19T00:00:00Z", Body: body,
		Sign: func(payload []byte, description string) (string, []byte, error) {
			if description != "POST "+server.URL+"/activate?selection=1" {
				t.Errorf("signer description=%q", description)
			}
			return ComputeDIDKey(pub), ed25519.Sign(key, payload), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 'x'
	target.Path = "/substitution"
	response, err := NewNoRedirectClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusTemporaryRedirect || redirected != 0 || string(received) != `{"operation":"activate"}` {
		t.Fatalf("status=%d redirects=%d body=%q", response.StatusCode, redirected, received)
	}
	encoded := headers.Get("X-AWEB-Signed-Payload")
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["method"] != "POST" || fields["path"] != "/activate?selection=1" || fields["did_aw"] != "did:aw:person" || headers.Get("X-AWEB-DID-AW") != "did:aw:person" || headers.Get("X-AWEB-Timestamp") != "2026-11-19T00:00:00Z" {
		t.Fatalf("wrong binding: %s headers=%v", payload, headers)
	}
	auth := strings.Fields(headers.Get("Authorization"))
	if len(auth) != 3 || auth[0] != "DIDKey" || auth[1] != ComputeDIDKey(pub) {
		t.Fatalf("authorization=%v", auth)
	}
	signature, err := base64.RawStdEncoding.DecodeString(auth[2])
	if err != nil || !ed25519.Verify(pub, payload, signature) {
		t.Fatal("request signature does not verify")
	}
}

func TestSignedIdentityPostRejectsMissingTargetOrInvalidChainBeforeSigning(t *testing.T) {
	calls := 0
	target, err := url.Parse("https://issuer.example/activate")
	if err != nil {
		t.Fatal(err)
	}
	input := SignedIdentityPost{Target: target, Chain: &IDChain{}, Sign: func([]byte, string) (string, []byte, error) { calls++; return "", nil, nil }}
	if _, err := NewSignedIdentityPostRequest(context.Background(), input); err == nil || calls != 0 {
		t.Fatalf("invalid chain signed: %v calls=%d", err, calls)
	}
	input.Target = nil
	input.Chain = nil
	if _, err := NewSignedIdentityPostRequest(context.Background(), input); err == nil || calls != 0 {
		t.Fatalf("missing target signed: %v calls=%d", err, calls)
	}
}
