package awid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newHostedE2EETestIdentity is an identity whose signed encryption key
// assertion says aweb's hosted service holds the key.
func newHostedE2EETestIdentity(t *testing.T, address string) e2eeTestIdentity {
	t.Helper()
	id := newE2EETestIdentity(t, address)
	id.assertion.Custody = EncryptionKeyCustodyHosted
	if err := SignEncryptionKeyAssertion(id.assertion, id.priv); err != nil {
		t.Fatal(err)
	}
	return id
}

func (id e2eeTestIdentity) resolved() *ResolvedIdentity {
	return &ResolvedIdentity{
		DID:           id.did,
		StableID:      id.stableID,
		Address:       id.address,
		PublicKey:     id.pub,
		EncryptionKey: id.assertion,
		Custody:       CustodySelf,
		IdentityScope: IdentityModeGlobal,
		ResolvedVia:   "registry",
	}
}

// custodialTestResolver answers from a fixed map. A did:key it does not
// know resolves to the bare key, with no encryption key, as did:key
// resolution does.
type custodialTestResolver map[string]*ResolvedIdentity

func (r custodialTestResolver) Resolve(_ context.Context, identifier string) (*ResolvedIdentity, error) {
	if identity, ok := r[identifier]; ok {
		return identity, nil
	}
	if strings.HasPrefix(identifier, "did:key:") {
		return &ResolvedIdentity{DID: identifier, Custody: CustodySelf, ResolvedVia: "did:key"}, nil
	}
	return nil, fmt.Errorf("not found: %s", identifier)
}

// sendRecorder is an aweb server that records every message or chat send
// and answers the reads a send makes first.
type sendRecorder struct {
	mu       sync.Mutex
	sends    []string
	mail     SendMessageRequest
	chat     ChatSendMessageRequest
	sessions []ChatSessionItem
	agents   []AgentView
	// refuseCustodial answers every send as a server that refuses an
	// encrypted send to a hosted recipient.
	refuseCustodial bool
}

const serverCustodialRefusalBody = `{"detail":"recipient_custodial_no_e2ee","reason":"recipient_custodial_no_e2ee","retryable":false,"correlation_id":"5b7f9a52-3c41-4e0b-9d7e-2f1a6c8b4e90"}`

func (s *sendRecorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Method == http.MethodPost && s.refuseCustodial {
			s.sends = append(s.sends, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(serverCustodialRefusalBody))
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			s.sends = append(s.sends, r.URL.Path)
			_ = json.NewDecoder(r.Body).Decode(&s.mail)
			_ = json.NewEncoder(w).Encode(SendMessageResponse{MessageID: s.mail.MessageID, ConversationID: s.mail.ConversationID, Status: "delivered"})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions"):
			s.sends = append(s.sends, r.URL.Path)
			_ = json.NewDecoder(r.Body).Decode(&s.chat)
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{MessageID: s.chat.MessageID, Delivered: true})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{Sessions: s.sessions})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages"):
			_ = json.NewEncoder(w).Encode(ChatHistoryResponse{})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(ListAgentsResponse{Agents: s.agents})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *sendRecorder) sent() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sends...)
}

func newCustodialTestClient(t *testing.T, serverURL string, self e2eeTestIdentity, resolver custodialTestResolver) *Client {
	t.Helper()
	c, err := NewWithIdentity(serverURL, self.priv, self.did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress(self.address)
	c.SetStableID(self.stableID)
	c.SetE2EEKey(self.assertion, self.xPriv)
	c.SetResolver(resolver)
	return c
}

func hostedRefusalText(address string) string {
	return address + " is a hosted agent: aweb's service reads its messages, so end-to-end encryption is not possible. Send it again without --e2ee."
}

func assertCustodialRefusal(t *testing.T, err error, want string, addresses ...string) {
	t.Helper()
	var refusal *CustodialRecipientError
	if !errors.As(err, &refusal) {
		t.Fatalf("err=%v, want the custodial recipient refusal", err)
	}
	if err.Error() != want {
		t.Fatalf("text=%q\nwant %q", err.Error(), want)
	}
	detail := DescribeError(err)
	if detail.Code != ErrorCodeRecipientCustodialNoE2EE {
		t.Fatalf("code=%q, want %q", detail.Code, ErrorCodeRecipientCustodialNoE2EE)
	}
	for _, address := range addresses {
		if !strings.Contains(detail.Detail, address) {
			t.Fatalf("detail %q does not name %s", detail.Detail, address)
		}
	}
}

// Mail to an address whose signed key assertion is hosted is refused before
// anything is sent.
func TestE2EEMailToHostedAddressIsRefusedBeforeSending(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	hosted := newHostedE2EETestIdentity(t, "aweb.ai/aida")
	rec := &sendRecorder{}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{hosted.address: hosted.resolved()})

	_, err := c.SendMessage(context.Background(), &SendMessageRequest{ToAddress: hosted.address, Subject: "hi", Body: "hi", EncryptE2EE: true})
	assertCustodialRefusal(t, err, hostedRefusalText(hosted.address), hosted.address)
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("refused mail was sent: %v", sent)
	}
}

// A self-custodial recipient still gets encrypted mail.
func TestE2EEMailToSelfCustodialAddressStillEncrypts(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	bob := newE2EETestIdentity(t, "example.com/bob")
	rec := &sendRecorder{}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{bob.address: bob.resolved()})

	if _, err := c.SendMessage(context.Background(), &SendMessageRequest{ToAddress: bob.address, Subject: "hi", Body: "hi", EncryptE2EE: true}); err != nil {
		t.Fatal(err)
	}
	if rec.mail.Encrypted == nil || rec.mail.ContentMode != ContentModeEncryptedV2 {
		t.Fatalf("mail to a self-custodial recipient was not encrypted: %#v", rec.mail)
	}
}

// Custody counts only from a signature-verified assertion: a projection
// that claims hosted custody without the identity's signature is not a
// hosted recipient, and its assertion is refused as invalid.
func TestE2EEMailUnsignedHostedClaimIsNotTheHostedRefusal(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	bob := newE2EETestIdentity(t, "example.com/bob")
	bob.assertion.Custody = EncryptionKeyCustodyHosted // not re-signed
	rec := &sendRecorder{}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{bob.address: bob.resolved()})

	_, err := c.SendMessage(context.Background(), &SendMessageRequest{ToAddress: bob.address, Subject: "hi", Body: "hi", EncryptE2EE: true})
	var refusal *CustodialRecipientError
	if err == nil || errors.As(err, &refusal) || !strings.Contains(err.Error(), "recipient encryption key assertion") {
		t.Fatalf("err=%v, want the invalid-assertion refusal, not the hosted one", err)
	}
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("mail was sent: %v", sent)
	}
}

// No published key is not read as hosted: it keeps its own refusal.
func TestE2EEMailNoPublishedKeyKeepsItsRefusal(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	bob := newE2EETestIdentity(t, "example.com/bob")
	keyless := bob.resolved()
	keyless.EncryptionKey = nil
	rec := &sendRecorder{}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{bob.address: keyless})

	_, err := c.SendMessage(context.Background(), &SendMessageRequest{ToAddress: bob.address, Subject: "hi", Body: "hi", EncryptE2EE: true})
	var refusal *CustodialRecipientError
	if err == nil || errors.As(err, &refusal) || !strings.Contains(err.Error(), "no published E2E encryption key") {
		t.Fatalf("err=%v, want the no-published-key refusal", err)
	}
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("mail was sent: %v", sent)
	}
}

// A roster agent whose signed assertion is hosted is refused too.
func TestE2EEMailToHostedRosterAgentIsRefused(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	hosted := newHostedE2EETestIdentity(t, "aweb.ai/aida")
	rec := &sendRecorder{agents: []AgentView{{AgentID: "agent-aida", Alias: "aida", DIDKey: hosted.did, DIDAW: hosted.stableID, Address: hosted.address}}}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{hosted.address: hosted.resolved()})

	_, err := c.SendMessage(context.Background(), &SendMessageRequest{ToAlias: "aida", Subject: "hi", Body: "hi", EncryptE2EE: true})
	assertCustodialRefusal(t, err, hostedRefusalText(hosted.address), hosted.address)
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("refused mail was sent: %v", sent)
	}
}

// A new chat with several recipients names every hosted one and sends to
// nobody.
func TestE2EEChatToHostedRecipientsNamesEachAndSendsNothing(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	aida := newHostedE2EETestIdentity(t, "aweb.ai/aida")
	bob := newE2EETestIdentity(t, "example.com/bob")
	nova := newHostedE2EETestIdentity(t, "aweb.ai/nova")
	rec := &sendRecorder{}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{
		aida.address: aida.resolved(), bob.address: bob.resolved(), nova.address: nova.resolved(),
	})

	_, err := c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{
		ToAddresses: []string{aida.address, bob.address, nova.address}, Message: "hi", EncryptE2EE: true,
	})
	want := "aweb.ai/aida and aweb.ai/nova are hosted agents: aweb's service reads their messages, so end-to-end encryption is not possible. Send it again without --e2ee."
	assertCustodialRefusal(t, err, want, aida.address, nova.address)
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("refused chat was sent: %v", sent)
	}
}

func continuationSession(self, peer e2eeTestIdentity) ChatSessionItem {
	return ChatSessionItem{
		SessionID:            "33333333-3333-4333-8333-333333333333",
		Participants:         []string{"self", "peer"},
		ParticipantDIDs:      []string{self.did, peer.did},
		ParticipantAddresses: []string{self.address, peer.address},
	}
}

// Continuing a chat a hosted agent started resolves its global address and
// refuses, rather than failing on the bare session did:key.
func TestE2EEChatContinuationWithHostedPeerIsRefused(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	hosted := newHostedE2EETestIdentity(t, "aweb.ai/aida")
	rec := &sendRecorder{sessions: []ChatSessionItem{continuationSession(self, hosted)}}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{hosted.address: hosted.resolved()})

	_, err := c.ChatSendMessage(context.Background(), "33333333-3333-4333-8333-333333333333", &ChatSendMessageRequest{Body: "reply", EncryptE2EE: true})
	assertCustodialRefusal(t, err, hostedRefusalText(hosted.address), hosted.address)
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("refused chat was sent: %v", sent)
	}
}

// Continuing a chat with a self-custodial global peer encrypts to the key
// its address resolves to.
func TestE2EEChatContinuationWithGlobalPeerEncrypts(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	bob := newE2EETestIdentity(t, "example.com/bob")
	rec := &sendRecorder{sessions: []ChatSessionItem{continuationSession(self, bob)}}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{bob.address: bob.resolved()})

	if _, err := c.ChatSendMessage(context.Background(), "33333333-3333-4333-8333-333333333333", &ChatSendMessageRequest{Body: "reply", EncryptE2EE: true}); err != nil {
		t.Fatal(err)
	}
	if rec.chat.Encrypted == nil || len(rec.chat.Encrypted.Recipients) != 1 || rec.chat.Encrypted.Recipients[0].DID != bob.did {
		t.Fatalf("continuation was not encrypted to the peer: %#v", rec.chat.Encrypted)
	}
}

// An address now held by a different identity is not the session's
// participant and is never used.
func TestE2EEChatContinuationIgnoresAReassignedAddress(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	bob := newE2EETestIdentity(t, "example.com/bob")
	newHolder := newE2EETestIdentity(t, "example.com/bob")
	rec := &sendRecorder{sessions: []ChatSessionItem{continuationSession(self, bob)}}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{bob.address: newHolder.resolved()})

	_, err := c.ChatSendMessage(context.Background(), "33333333-3333-4333-8333-333333333333", &ChatSendMessageRequest{Body: "reply", EncryptE2EE: true})
	if err == nil || !strings.Contains(err.Error(), "no published E2E encryption key") {
		t.Fatalf("err=%v, want today's refusal, not a send to the new holder", err)
	}
	if sent := rec.sent(); len(sent) != 0 {
		t.Fatalf("chat was sent to a reassigned address: %v", sent)
	}
}

// A server that refuses an encrypted send to a hosted recipient with its
// stable reason gets the same text and code as the client's own refusal.
func TestE2EEServerCustodialRefusalReadsLikeTheClients(t *testing.T) {
	self := newE2EETestIdentity(t, "example.com/self")
	bob := newE2EETestIdentity(t, "example.com/bob")
	rec := &sendRecorder{refuseCustodial: true}
	c := newCustodialTestClient(t, rec.server(t).URL, self, custodialTestResolver{bob.address: bob.resolved()})

	_, err := c.SendMessage(context.Background(), &SendMessageRequest{ToAddress: bob.address, Subject: "hi", Body: "hi", EncryptE2EE: true})
	assertCustodialRefusal(t, err, hostedRefusalText(bob.address), bob.address)
	if status, ok := HTTPStatusCode(err); !ok || status != http.StatusUnprocessableEntity {
		t.Fatalf("mail refusal lost the server status: %v", err)
	}
	_, err = c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{ToAddresses: []string{bob.address}, Message: "hi", EncryptE2EE: true})
	assertCustodialRefusal(t, err, hostedRefusalText(bob.address), bob.address)
}
