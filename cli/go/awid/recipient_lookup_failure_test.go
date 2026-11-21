package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// localSenderFixture is a local sender (no did:aw, no address) in
// backend:acme.com whose team has kestrel, a local member, and whose registry
// answers every address lookup with registryStatus. Recipient binding is not
// required by configuration.
type localSenderFixture struct {
	client     *Client
	kestrelDID string
	sent       map[string]any
}

func newLocalSenderFixture(t *testing.T, registryStatus int) *localSenderFixture {
	t.Helper()
	f := &localSenderFixture{}
	_, kestrelKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.kestrelDID = ComputeDIDKey(kestrelKey.Public().(ed25519.PublicKey))
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(registryStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": http.StatusText(registryStatus)})
	}))
	t.Cleanup(registry.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(ListAgentsResponse{
				TeamID: "backend:acme.com",
				Agents: []AgentView{{Alias: "kestrel", DIDKey: f.kestrelDID, IdentityScope: IdentityModeLocal}},
			})
		case "/v1/messages", "/v1/chat/sessions":
			if err := json.NewDecoder(r.Body).Decode(&f.sent); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"message_id": "m1", "conversation_id": "c1", "session_id": "s1"})
		case "/health":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected server path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	_, senderKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewWithCertificate(server.URL, senderKey, testTeamCertificate(t, senderKey, "bodhi"))
	if err != nil {
		t.Fatal(err)
	}
	registryResolver := NewRegistryResolver(nil, nil)
	routeUntrustedResolverRegistriesToInjectedClient(registryResolver)
	if err := registryResolver.SetFallbackRegistryURL(registry.URL); err != nil {
		t.Fatal(err)
	}
	client.SetResolver(&ChainResolver{Registry: registryResolver, Team: &TeamRosterResolver{Client: client, TeamID: "backend:acme.com"}})
	f.client = client
	return f
}

func (f *localSenderFixture) send(t *testing.T, kind receivedKind, target string) error {
	t.Helper()
	if kind == receivedMail {
		_, err := f.client.SendMessageByIdentity(context.Background(), &SendMessageRequest{ToAddress: target, Body: "hi"})
		return err
	}
	_, err := f.client.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{ToAddresses: []string{target}, Message: "hi"})
	return err
}

// A local sender's send to an address whose recipient key cannot be looked up
// is posted unsigned to a recipient key, and the server resolves the address,
// as released aw does: a local seat does not depend on the registry
// answering. The neighbour, a member of the sender's own team named by full
// address, is bound by the team roster.
func TestLocalSenderPostsAnAddressWhoseRecipientKeyCannotBeLookedUp(t *testing.T) {
	for _, kind := range []receivedKind{receivedMail, receivedChat} {
		for _, registryStatus := range []int{http.StatusServiceUnavailable, http.StatusNotFound} {
			f := newLocalSenderFixture(t, registryStatus)
			if err := f.send(t, kind, "other.com/carol"); err != nil {
				t.Fatalf("%s, registry %d: %v", kind, registryStatus, err)
			}
			if f.sent == nil {
				t.Fatalf("%s, registry %d: nothing was posted", kind, registryStatus)
			}
			var signed map[string]any
			if err := json.Unmarshal([]byte(f.sent["signed_payload"].(string)), &signed); err != nil {
				t.Fatal(err)
			}
			if signed["to"] != "other.com/carol" || signed["to_did"] != "" {
				t.Fatalf("%s, registry %d: signed to=%v to_did=%v, want the address unbound", kind, registryStatus, signed["to"], signed["to_did"])
			}
		}

		f := newLocalSenderFixture(t, http.StatusNotFound)
		if err := f.send(t, kind, "acme.com/kestrel"); err != nil {
			t.Fatalf("%s to own team member: %v", kind, err)
		}
		toDID := f.sent["to_did"]
		if kind == receivedChat {
			var signed map[string]any
			if err := json.Unmarshal([]byte(f.sent["signed_payload"].(string)), &signed); err != nil {
				t.Fatal(err)
			}
			toDID = signed["to_did"]
		}
		if toDID != f.kestrelDID {
			t.Fatalf("%s to own team member signed to_did %v, want %s", kind, toDID, f.kestrelDID)
		}
	}
}
