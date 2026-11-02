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

// ownTeamAddressFixture is a global sender in backend:acme.com whose team has
// kestrel, a local member with no AWID address, and whose registry knows no
// acme.com address.
type ownTeamAddressFixture struct {
	client      *Client
	kestrelDID  string
	sent        map[string]any
	addressGets int
}

func newOwnTeamAddressFixture(t *testing.T) *ownTeamAddressFixture {
	t.Helper()
	f := &ownTeamAddressFixture{}
	_, kestrelKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.kestrelDID = ComputeDIDKey(kestrelKey.Public().(ed25519.PublicKey))
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/namespaces/acme.com/addresses/") {
			f.addressGets++
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Address not found"})
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
	client.SetAddress("acme.com/bodhi")
	client.SetStableID(ComputeStableID(senderKey.Public().(ed25519.PublicKey)))
	client.SetRequireRecipientBindingForDirectAddresses(true)
	registryResolver := NewRegistryResolver(nil, nil)
	if err := registryResolver.SetFallbackRegistryURL(registry.URL); err != nil {
		t.Fatal(err)
	}
	client.SetResolver(&ChainResolver{Registry: registryResolver, Team: &TeamRosterResolver{Client: client, TeamID: "backend:acme.com"}})
	f.client = client
	return f
}

// A global sender reaches a local member of its own team by full address, as
// it does by alias. AWID is asked first and has no such address; the
// authenticated team roster then binds the recipient's key
// (docs/messaging-contract-matrix.md, case 2).
func TestGlobalSenderReachesOwnTeamLocalMemberByFullAddress(t *testing.T) {
	f := newOwnTeamAddressFixture(t)
	if _, err := f.client.SendMessageByIdentity(context.Background(), &SendMessageRequest{ToAddress: "acme.com/kestrel", Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	if f.sent["to_did"] != f.kestrelDID || f.sent["to_address"] != "acme.com/kestrel" {
		t.Fatalf("sent %v", f.sent)
	}
	if f.addressGets != 1 {
		t.Fatalf("AWID was asked %d times, want once before the roster", f.addressGets)
	}

	chat := newOwnTeamAddressFixture(t)
	if _, err := chat.client.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{ToAddresses: []string{"acme.com/kestrel"}, Message: "hi"}); err != nil {
		t.Fatal(err)
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(chat.sent["signed_payload"].(string)), &signed); err != nil {
		t.Fatal(err)
	}
	if signed["to_did"] != chat.kestrelDID || chat.addressGets != 1 {
		t.Fatalf("chat signed %v after %d AWID reads", signed, chat.addressGets)
	}
}

// An address that neither the sender's team roster nor AWID knows is refused,
// and the refusal says why: a local identity has no address.
func TestUnregisteredAddressRefusalSaysWhy(t *testing.T) {
	for _, target := range []string{"acme.com/nobody", "other.com/kestrel"} {
		f := newOwnTeamAddressFixture(t)
		_, err := f.client.SendMessageByIdentity(context.Background(), &SendMessageRequest{ToAddress: target, Body: "hi"})
		var refusal *RecipientResolutionError
		if !errors.As(err, &refusal) || f.sent != nil {
			t.Fatalf("%s: err %v sent %v", target, err, f.sent)
		}
		for _, want := range []string{target + " is not a registered address", "local identity", "inside its own team, by alias"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refusal %q does not say %q", err.Error(), want)
			}
		}
	}
}
