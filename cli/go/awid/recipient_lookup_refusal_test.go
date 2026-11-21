package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// A send to an address whose recipient key cannot be looked up is refused,
// whoever sends it: a local sender's mail and chat are never signed without
// the recipient's key (docs/identity-messaging-contract.md:119-129). The
// neighbour, a member of the sender's own team named by full address, is
// bound by the team roster and sent.
func TestLocalSenderRefusesAnAddressWhoseRecipientKeyCannotBeLookedUp(t *testing.T) {
	for _, kind := range []receivedKind{receivedMail, receivedChat} {
		for _, registryStatus := range []int{http.StatusServiceUnavailable, http.StatusNotFound} {
			f := newLocalSenderFixture(t, registryStatus)
			err := f.send(t, kind, "other.com/carol")
			var refusal *RecipientResolutionError
			if !errors.As(err, &refusal) || f.sent != nil {
				t.Fatalf("%s, registry %d: err %v, sent %v", kind, registryStatus, err, f.sent)
			}
			want := "other.com/carol is not a registered address"
			if registryStatus != http.StatusNotFound {
				want = "Nothing was sent: a " + string(kind) + " is signed with its recipient's key, which could not be looked up; send it again when the registry answers"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s, registry %d: refusal %q does not say %q", kind, registryStatus, err, want)
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
