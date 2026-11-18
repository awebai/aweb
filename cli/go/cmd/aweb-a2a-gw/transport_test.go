package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/a2agw"
	"github.com/awebai/aw/awid"
)

func TestManagedSecretsRequireSecureDestinations(t *testing.T) {
	for _, raw := range []string{"http://control.example/config", "http://localhost/config", "https://user:secret@control.example/config"} {
		if err := validateManagedURL(managedURL{Field: "config_url", Value: raw}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatalf("unsafe managed destination %q accepted: %v", raw, err)
		}
		if strings.HasPrefix(raw, "http://localhost") {
			err := validateManagedURL(managedURL{Field: "config_url", Value: raw})
			if err == nil || !strings.Contains(err.Error(), "http://127.0.0.1") {
				t.Fatalf("localhost refusal must name the usable loopback URL: %v", err)
			}
		}
	}
	for _, raw := range []string{"https://control.example/config", "http://127.0.0.1:8080/config", "http://[::1]:8080/config"} {
		if err := validateManagedURL(managedURL{Field: "config_url", Value: raw}); err != nil {
			t.Fatalf("valid destination %q: %v", raw, err)
		}
	}
}

func TestManagedReplyUsesMailVerificationInsteadOfProviderLabels(t *testing.T) {
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	env := &awid.MessageEnvelope{FromDID: did, Type: "mail", MessageID: "reply", ConversationID: "thread", Subject: "Reply", Body: "signed answer", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	signature, err := awid.SignMessage(key, env)
	if err != nil {
		t.Fatal(err)
	}
	msg := awid.InboxMessage{MessageID: "reply", ConversationID: "thread", FromDID: did, Subject: "Reply", Body: "signed answer", SignedPayload: awid.CanonicalJSON(env), Signature: signature, VerificationStatus: awid.Verified}
	var msgMu sync.RWMutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msgMu.RLock()
		defer msgMu.RUnlock()
		if err := json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{msg}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	transport, err := managedBridgeTransportFromConfig(fileConfig{ManagedConfig: managedConfigForTest(server.URL, "gw", "token")})
	if err != nil {
		t.Fatal(err)
	}
	read := func() awid.VerificationStatus {
		t.Helper()
		out, err := transport.MailConversation(context.Background(), "thread", 10)
		if err != nil || len(out.Messages) != 1 {
			t.Fatalf("read reply: %#v %v", out, err)
		}
		return out.Messages[0].VerificationStatus
	}
	if got := read(); got != awid.Verified {
		t.Fatalf("valid signed reply: %s", got)
	}
	msgMu.Lock()
	msg.Body = "provider replaced the signed answer"
	msgMu.Unlock()
	if got := read(); got != awid.Failed {
		t.Fatalf("provider label hid modified content: %s", got)
	}
}

func TestVerifiedManagedRouteRequiresRecipientIdentityCapabilityBeforeSend(t *testing.T) {
	var payload managedRuntimeConfigPayload
	data := `{"gateway_id":"gw","gateway_identity":"did:aw:gateway","gateway_identity_status":"active","config_revision":"1","expires_at":"2099-01-01T00:00:00Z","routes":[{"route_id":"r","address":"example.com/agent","mode":"mail","card":{"name":"Agent","description":"Agent","provider":{"organization":"Example","url":"https://example.com"},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"reply","name":"Reply","description":"Reply"}]}}]}`
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatal(err)
	}
	cfg := fileConfig{Host: "gateway.example", ManagedConfig: managedConfigForTest("https://provider.example", "gw", "token")}
	if err := mergeManagedRuntimeConfig(&cfg, payload); err == nil || !strings.Contains(err.Error(), "provider.example") || !strings.Contains(err.Error(), "recipient_identity_v1") {
		t.Fatalf("verified route accepted old provider: %v", err)
	}
	require := false
	cfg.RequireVerifiedReplies, cfg.AllowUnverifiedLocalReply = &require, true
	if err := mergeManagedRuntimeConfig(&cfg, payload); err != nil {
		t.Fatalf("explicit unverified route must remain supported: %v", err)
	}
}

func TestGatewayBoundsSlowRequestBodies(t *testing.T) {
	handler, err := a2agw.New(a2agw.Config{Host: "example.com", Routes: []a2agw.Route{{RouteID: "slow", Address: "example.com/slow", Card: a2agw.RouteCard{Name: "Slow", Description: "Slow body test", Provider: a2a.Provider{Organization: "Example", URL: "https://example.com"}, Skills: []a2a.Skill{{ID: "reply", Name: "Reply", Description: "Reply"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config = gatewayHTTPServer("", handler)
	server.Start()
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "POST /a2a/agents/slow/rpc HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("slow request body was not bounded by the server: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusRequestTimeout || !strings.Contains(string(body), "Retry with a complete JSON body") {
		t.Fatalf("wrong timeout refusal: status=%d body=%s", response.StatusCode, body)
	}
}
