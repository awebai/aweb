package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	aweb "github.com/awebai/aw"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestCustodyStoredMailReply(t *testing.T) {
	for _, scenario := range []string{"valid", "forged-target", "forged-assertion", "addressed-source", "archive-only", "self-sender", "routing", "recipient-routing", "extra-recipient", "no-read", "missing-source", "forged-source", "expired-assertion", "missing-assertion", "wrong-conversation", "wrong-source-id", "nonce-source-substitution", "first-contact", "remote-source", "resident-http-read", "replay-read-revoked"} {
		t.Run(scenario, func(t *testing.T) {
			resident := newCustodyE2EETestIdentity(t, "example.com/resident")
			human := newCustodyE2EETestIdentity(t, "example.com/human")
			human.address = ""
			_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
			svc := testCustodyE2EEService(t, resident, human, sessionKey)
			req := signedE2EECreateRequest(t, sessionKey, resident, human)
			sourceID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
			req.ReplyToMessageID = sourceID
			createdAt := time.Now().UTC()
			sender, recipient := human, resident
			if scenario == "addressed-source" {
				sender.address = "example.com/human"
			}
			if scenario == "archive-only" || scenario == "self-sender" {
				sender, recipient = resident, human
				sender.address = ""
			}
			if scenario == "expired-assertion" {
				createdAt = createdAt.Add(-time.Hour)
				for _, identity := range []custodyE2EETestIdentity{resident, human} {
					identity.assertion.CreatedAt = createdAt.Add(-time.Hour).Format(time.RFC3339)
					identity.assertion.NotBefore = identity.assertion.CreatedAt
					if identity.did == human.did {
						identity.assertion.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
					}
					if err := awid.SignEncryptionKeyAssertion(identity.assertion, identity.signKey); err != nil {
						t.Fatal(err)
					}
				}
			}
			source, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
				Sender:     awid.E2EESenderKey{DID: sender.did, StableID: sender.stableID, Address: sender.address, EncryptionKey: sender.assertion, SigningKey: sender.signKey},
				Recipients: []awid.E2EERecipientKey{{DID: recipient.did, StableID: recipient.stableID, Address: recipient.address, EncryptionKey: recipient.assertion}},
				MessageID:  sourceID, ConversationID: req.ConversationID, Body: "source", CreatedAt: createdAt,
			})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "self-sender" {
				// Unlike archive-only, this source also has a real delivery wrap
				// to the resident; being one's own sender must still be refused.
				source, err = awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
					Sender:     awid.E2EESenderKey{DID: resident.did, StableID: resident.stableID, EncryptionKey: resident.assertion, SigningKey: resident.signKey},
					Recipients: []awid.E2EERecipientKey{{DID: resident.did, StableID: resident.stableID, Address: resident.address, EncryptionKey: resident.assertion}},
					MessageID:  sourceID, ConversationID: req.ConversationID, Body: "self", CreatedAt: createdAt,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			reads := 0
			svc.readStoredMailReply = func(_ context.Context, id string) (*awid.InboxMessage, error) {
				reads++
				if id != req.ReplyToMessageID {
					t.Fatal("wrong source read")
				}
				if scenario == "missing-source" {
					return nil, nil
				}
				actor := "human-actor"
				if scenario == "remote-source" {
					actor = ""
				}
				return &awid.InboxMessage{MessageID: source.MessageID, ConversationID: source.ConversationID, FromAgentID: actor, Encrypted: source}, nil // Custody checks IDs itself.
			}
			if scenario == "resident-http-read" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reads++
					if r.Method != "GET" || r.URL.Path != "/v1/messages/"+sourceID {
						t.Errorf("wrong stored source read: %s", r.URL.Path)
						http.NotFound(w, r)
						return
					}
					if !strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey "+resident.did+" ") {
						t.Error("source read not signed by resident")
					}
					_ = json.NewEncoder(w).Encode(awid.InboxMessage{MessageID: sourceID, ConversationID: source.ConversationID, FromAgentID: "human-actor", Encrypted: source})
				}))
				defer server.Close()
				client, err := awid.NewWithIdentity(server.URL, resident.signKey, resident.did)
				if err != nil {
					t.Fatal(err)
				}
				svc.client = &aweb.Client{Client: client}
				svc.readStoredMailReply = svc.storedMailReplyViaClient
			}
			switch scenario {
			case "forged-target":
				req.Recipients[0].DID = resident.did
			case "forged-assertion":
				forged := *human.assertion
				forged.Signature = "forged"
				req.Recipients[0].EncryptionKey = &forged
			case "routing":
				req.DeliveryOrigin = "https://other.example"
			case "recipient-routing":
				req.Recipients[0].InboundMode = "open"
			case "extra-recipient":
				req.Recipients = append(req.Recipients, req.Recipients[0])
			case "no-read":
				original := svc.grantStatus
				svc.grantStatus = func(ctx context.Context, id string) (custodyGrantStatus, error) {
					status, err := original(ctx, id)
					status.Scopes = []string{"mail.send"}
					return status, err
				}
			case "forged-source":
				source.Signature = "forged"
			case "missing-assertion":
				source.SenderEncryptionKey = nil // also invalidates source signature; fail before any key is used.
			case "wrong-conversation":
				req.ConversationID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			case "wrong-source-id":
				req.ReplyToMessageID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			case "first-contact":
				req.ReplyToMessageID = ""
			}
			if err := awid.SignE2EECreateCustodyProof(sessionKey, req); err != nil {
				t.Fatal(err)
			}
			out, err := svc.createE2EEEnvelope(context.Background(), req)
			if scenario != "valid" && scenario != "nonce-source-substitution" && scenario != "resident-http-read" && scenario != "replay-read-revoked" {
				if err == nil || out != nil {
					t.Fatalf("%s accepted: %+v", scenario, out)
				}
				if scenario == "archive-only" && err.Error() != "not_a_delivery_recipient" {
					t.Fatal(err)
				}
				if scenario == "self-sender" && err.Error() != "reply_source_is_resident" {
					t.Fatal(err)
				}
				if scenario == "expired-assertion" && !strings.Contains(err.Error(), "send a new message") {
					t.Fatal(err)
				}
				if scenario == "no-read" && (err.Error() != "grant_scope_denied" || reads != 0) {
					t.Fatalf("scope err=%v reads=%d", err, reads)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if reads != 1 {
				t.Fatalf("stored read count=%d", reads)
			}
			envelope := out.EncryptedEnvelope
			if envelope.ReplyToMessageID != sourceID {
				t.Fatal("missing signed source id")
			}
			if err := awid.VerifyE2EEMessageEnvelopeSignature(envelope); err != nil {
				t.Fatal(err)
			}
			archived := false
			for _, wrap := range envelope.KeyWraps {
				if wrap.WrapPurpose == "sender_copy" && wrap.RecipientDID == resident.did {
					archived = true
				}
			}
			if !archived {
				t.Fatal("missing resident archive wrap")
			}
			plain, err := awid.DecryptE2EEMessage(envelope, awid.E2EEDecryptIdentity{DID: human.did, StableID: human.stableID, EncryptionKeyID: human.assertion.EncryptionKeyID, PrivateKey: human.xPriv})
			if err != nil || plain.Body != req.Body {
				t.Fatalf("human decrypt: %v", err)
			}
			if scenario == "replay-read-revoked" {
				original := svc.grantStatus
				svc.grantStatus = func(ctx context.Context, id string) (custodyGrantStatus, error) {
					status, err := original(ctx, id)
					status.Scopes = []string{"mail.send"}
					return status, err
				}
				if _, err := svc.createE2EEEnvelope(context.Background(), req); err == nil || err.Error() != "grant_scope_denied" {
					t.Fatalf("cached reply bypassed read scope: %v", err)
				}
			}
			if scenario == "nonce-source-substitution" {
				changed := *req
				changed.ReplyToMessageID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
				if err := awid.SignE2EECreateCustodyProof(sessionKey, &changed); err != nil {
					t.Fatal(err)
				}
				changed.Nonce = req.Nonce
				if _, err := svc.createE2EEEnvelope(context.Background(), &changed); err == nil || err.Error() != "replay_detected" {
					t.Fatalf("changed source replay: %v", err)
				}
			}
		})
	}
}
