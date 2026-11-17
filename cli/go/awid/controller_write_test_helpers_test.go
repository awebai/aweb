package awid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// coveringPayloadFor is the covering-v2 payload a controller signs for fields
// (domain, operation and timestamp, and the operation's claims) over exactly
// the request r, checked against r's X-AWEB-Signed-Payload. r's body is
// restored for the handler to read.
func coveringPayloadFor(t *testing.T, r *http.Request, fields map[string]string) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		body = nil
	}
	claims := map[string]any{}
	for k, v := range fields {
		if k != "domain" && k != "operation" && k != "timestamp" {
			claims[k] = v
		}
	}
	payload, err := ControllerRequestPayload("http://"+r.Host, r.Method, r.URL.EscapedPath(), body,
		fields["timestamp"], fields["domain"], fields["operation"], claims)
	if err != nil {
		t.Fatalf("covering payload: %v", err)
	}
	signed, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil || !bytes.Equal(signed, payload) {
		t.Fatalf("signed payload %s, want %s", signed, payload)
	}
	return string(payload)
}

// An empty registry URL is the client's default registry, as it was before
// writes were signed in the covering form.
func TestControllerWriteWithoutRegistryURLUsesTheDefaultRegistry(t *testing.T) {
	_, controllerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		coveringPayloadFor(t, r, map[string]string{
			"domain": "acme.com", "operation": "create_team", "name": "backend",
			"timestamp": r.Header.Get("X-AWEB-Timestamp"),
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "domain": "acme.com", "name": "backend"})
	}))
	t.Cleanup(server.Close)
	client := NewAWIDRegistryClient(server.Client(), nil)
	client.DefaultRegistryURL = server.URL
	routeUntrustedRegistriesToInjectedClient(client)
	if _, err := client.CreateTeam(context.Background(), "", "acme.com", "backend", "Backend", "did:key:z6MkteamKey", controllerKey); err != nil {
		t.Fatalf("create team at the default registry: %v", err)
	}
	if !reached {
		t.Fatal("the write did not reach the default registry")
	}
}
