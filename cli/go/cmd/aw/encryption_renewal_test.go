package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestEncryptionAssertionRenewalSameKey(t *testing.T) {
	t.Setenv(awconfig.IdentityHomeEnv, "")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, age := range []time.Duration{80 * 24 * time.Hour, 100 * 24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			pub, key, _ := awid.GenerateKeypair()
			did := awid.ComputeDIDKey(pub)
			publications := make(chan *awid.EncryptionKeyAssertion, 4)
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox" {
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
					return
				}
				if r.Method != http.MethodPut || r.URL.Path != "/v1/agents/me/encryption-key" {
					http.NotFound(w, r)
					return
				}
				var a awid.EncryptionKeyAssertion
				if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
					t.Error(err)
				}
				if err := awid.VerifyEncryptionKeyAssertion(&a, did, "", time.Now()); err != nil {
					t.Error(err)
				}
				publications <- &a
				_ = json.NewEncoder(w).Encode(map[string]any{"encryption_key": a})
			}))
			writeMessagingPrincipalForTest(t, root, server.URL, "alice", did, key)
			home := filepath.Join(root, ".aw")
			assertion := installMailReadEncryptionKeyForTest(t, root, home, did, key)
			statePath := filepath.Join(home, "encryption.yaml")
			state, _ := awconfig.LoadEncryptionKeyStateFrom(statePath)
			record := state.ActiveRecord()
			private, err := awid.LoadX25519PrivateKey(filepath.Join(home, record.PrivateKeyPath))
			if err != nil {
				t.Fatal(err)
			}
			old, err := awid.BuildEncryptionKeyAssertion(key, did, "", private.PublicKey().Bytes(), "", time.Now().Add(-age))
			if err != nil {
				t.Fatal(err)
			}
			if err := saveEncryptionAssertion(filepath.Join(home, record.AssertionPath), old); err != nil {
				t.Fatal(err)
			}
			record.ExpiresAt = old.ExpiresAt
			state.UpsertRecord(*record)
			if err := awconfig.SaveEncryptionKeyStateTo(statePath, state); err != nil {
				t.Fatal(err)
			}
			run := exec.CommandContext(ctx, bin, "--identity-home", home, "mail", "inbox")
			run.Dir = root
			run.Env = testCommandEnv(root)
			if out, err := run.CombinedOutput(); err != nil {
				t.Fatalf("renew on inbox: %v %s", err, out)
			}
			var published *awid.EncryptionKeyAssertion
			select {
			case published = <-publications:
			default:
				t.Fatal("no renewed assertion published")
			}
			if published == nil || published.EncryptionKeyID != assertion.EncryptionKeyID || published.EncryptionPublicKey != assertion.EncryptionPublicKey {
				t.Fatalf("same key not published: %+v", published)
			}
			state, _ = awconfig.LoadEncryptionKeyStateFrom(statePath)
			if len(state.Keys) != 1 || state.ActiveKeyID != assertion.EncryptionKeyID || state.ActiveRecord().PublishedAt == "" {
				t.Fatalf("key state: %+v", state)
			}
			again := exec.CommandContext(ctx, bin, "--identity-home", home, "mail", "inbox")
			again.Dir, again.Env = root, testCommandEnv(root)
			if out, err := again.CombinedOutput(); err != nil {
				t.Fatalf("fresh assertion command: %v %s", err, out)
			}
			select {
			case <-publications:
				t.Fatal("fresh assertion unnecessarily republished")
			default:
			}
			peer := newCustodyE2EETestIdentity(t, "example.test/peer")
			// Real crypto: a peer accepts the renewed assertion, encrypts, and the old private key decrypts.
			envelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{DID: peer.did, StableID: peer.stableID, Address: peer.address, SigningKey: peer.signKey, EncryptionKey: peer.assertion}, Recipients: []awid.E2EERecipientKey{{DID: did, EncryptionKey: published}}, Subject: "renewed", Body: "same private key", MessageID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			plain, err := awid.DecryptE2EEMessage(envelope, awid.E2EEDecryptIdentity{DID: did, EncryptionKeyID: assertion.EncryptionKeyID, PrivateKey: private})
			if err != nil || plain.Body != "same private key" {
				t.Fatalf("decrypt: %v %+v", err, plain)
			}
			if age > 90*24*time.Hour {
				_, err = awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{DID: peer.did, StableID: peer.stableID, Address: peer.address, SigningKey: peer.signKey, EncryptionKey: peer.assertion}, Recipients: []awid.E2EERecipientKey{{DID: did, EncryptionKey: old}}, Body: "must fail", MessageID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Now()})
				if err == nil || !strings.Contains(err.Error(), "expired") {
					t.Fatalf("expired recipient error: %v", err)
				}
			}
		})
	}
}

func TestCustodyRenewsExpiredAssertionWithoutGrantActivity(t *testing.T) {
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := awid.GenerateKeypair()
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	published := make(chan *awid.EncryptionKeyAssertion, 2)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !(r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key") && !(r.Method == http.MethodPost && r.URL.Path == "/v1/did/"+stableID+"/encryption-key") {
			http.NotFound(w, r)
			return
		}
		var a awid.EncryptionKeyAssertion
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			t.Error(err)
		}
		if err := awid.VerifyEncryptionKeyAssertion(&a, did, stableID, time.Now()); err != nil {
			t.Error(err)
		}
		published <- &a
		_ = json.NewEncoder(w).Encode(map[string]any{"encryption_key": a})
	}))
	writeMessagingPrincipalForTest(t, root, server.URL, "alice", did, key)
	writeIdentityForTest(t, root, awconfig.WorktreeIdentity{DID: did, StableID: stableID, Address: "example.test/alice", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: server.URL, RegistryStatus: "registered"})
	home := filepath.Join(root, ".aw")
	a := installMailReadEncryptionKeyForTest(t, root, home, did, key)
	state, _ := awconfig.LoadEncryptionKeyStateFrom(filepath.Join(home, "encryption.yaml"))
	record := state.ActiveRecord()
	a.IdentityStableID = &stableID
	a.CreatedAt = time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339)
	a.NotBefore = a.CreatedAt
	a.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := awid.SignEncryptionKeyAssertion(a, key); err != nil {
		t.Fatal(err)
	}
	if err := saveEncryptionAssertion(filepath.Join(home, record.AssertionPath), a); err != nil {
		t.Fatal(err)
	}
	identity, err := resolveIdentityForEncryptionKeyForDir(root, explicitEncryptionKeyIdentityHome(home))
	if err != nil {
		t.Fatal(err)
	}
	// Custody can load the expired active private key before renewal succeeds.
	_, private, err := loadCustodyE2EEKey(home, identity)
	if err != nil {
		t.Fatal(err)
	}
	svc := &custodyService{residentHome: home}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { svc.renewEncryptionAssertions(ctx); close(done) }()
	for range 2 {
		select {
		case renewed := <-published:
			if renewed.EncryptionKeyID != a.EncryptionKeyID || renewed.EncryptionPublicKey != a.EncryptionPublicKey {
				t.Fatal("custody rotated key")
			}
			if err := awid.VerifyEncryptionKeyAssertion(renewed, did, stableID, time.Now()); err != nil {
				t.Fatal(err)
			}
			if got, _ := awid.ComputeEncryptionKeyID(private.PublicKey().Bytes()); got != renewed.EncryptionKeyID {
				t.Fatal("private key changed")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("custody did not renew without grant traffic")
		}
	}
	cancel()
	<-done
	// Expiry tolerance must not tolerate tampering, even with an expired assertion.
	a.Signature = strings.Repeat("A", len(a.Signature))
	if err := saveEncryptionAssertion(filepath.Join(home, record.AssertionPath), a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCustodyE2EEKey(home, identity); err == nil {
		t.Fatal("custody accepted tampered expired assertion")
	}
}
