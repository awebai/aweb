package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientPresentsIDChainOutsideSignedRequestBody(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rootPub, rootKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": ComputeDIDKey(pub), "domain": "example.test", "parent": map[string]any{"kind": "namespace", "id": "example.test"}, "kind": "agent", "issuer_key": ComputeDIDKey(rootPub), "issued_at": "2026-10-30T00:00:00Z"}
	payload, err := IDCertificateSigningBytes(cert)
	if err != nil {
		t.Fatal(err)
	}
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{map[string]any{"certificate": cert, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootKey, payload))}}}
	expected, err := EncodeIDChainHeader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var headers []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = append(headers, r.Header.Get("X-AWID-ID-Chain"))
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"body":"unchanged"}` {
			t.Errorf("body changed: %s", b)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("original request auth missing")
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := NewWithIdentity(server.URL, key, ComputeDIDKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Post(context.Background(), "/v1/messages", map[string]string{"body": "unchanged"}, nil); err != nil {
		t.Fatal(err)
	}
	if err = client.SetIDChain(bundle); err != nil {
		t.Fatal(err)
	}
	if err = client.Post(context.Background(), "/v1/messages", map[string]string{"body": "unchanged"}, nil); err != nil {
		t.Fatal(err)
	}
	if err = client.SetIDChain(nil); err != nil {
		t.Fatal(err)
	}
	if err = client.Post(context.Background(), "/v1/messages", map[string]string{"body": "unchanged"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(headers) != 3 || headers[0] != "" || headers[1] != expected || headers[2] != "" {
		t.Fatalf("headers = %#v", headers)
	}
	if err = client.SetIDChain(map[string]any{"v": 1}); err == nil {
		t.Fatal("malformed chain accepted")
	}
}
