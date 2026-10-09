package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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
			previousKeyID := newCustodyE2EETestIdentity(t, "example.test/previous").assertion.EncryptionKeyID
			old, err := awid.BuildEncryptionKeyAssertion(key, did, "", private.PublicKey().Bytes(), previousKeyID, time.Now().Add(-age))
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
			if published.PreviousEncryptionKeyID == nil || *published.PreviousEncryptionKeyID != previousKeyID {
				t.Fatal("renewal changed previous-key linkage")
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

func TestEncryptionRenewalFailureBackoffAcrossCommands(t *testing.T) {
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := awid.GenerateKeypair()
	did := awid.ComputeDIDKey(pub)
	var attempts atomic.Int32
	var accept atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key" {
			attempts.Add(1)
			if !accept.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			var a awid.EncryptionKeyAssertion
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
				t.Error(err)
			}
			if err := awid.VerifyEncryptionKeyAssertion(&a, did, "", time.Now()); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_key": a})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox" {
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
			return
		}
		http.NotFound(w, r)
	}))
	writeMessagingPrincipalForTest(t, root, server.URL, "alice", did, key)
	home := filepath.Join(root, ".aw")
	a := installMailReadEncryptionKeyForTest(t, root, home, did, key)
	statePath := filepath.Join(home, "encryption.yaml")
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		t.Fatal(err)
	}
	record := state.ActiveRecord()
	a.CreatedAt = time.Now().Add(-80 * 24 * time.Hour).UTC().Format(time.RFC3339)
	a.NotBefore = a.CreatedAt
	a.ExpiresAt = time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := awid.SignEncryptionKeyAssertion(a, key); err != nil {
		t.Fatal(err)
	}
	if err := saveEncryptionAssertion(filepath.Join(home, record.AssertionPath), a); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	run := func(args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, bin, append([]string{"--identity-home", home}, args...)...)
		command.Dir, command.Env = root, testCommandEnv(root)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("command %v: %v %s", args, err, out)
		}
		return string(out)
	}
	before := fileDigestsForTest(t, home)
	for _, args := range [][]string{{"version"}, {"help"}, {"upgrade"}, {"mail", "inbox", "--help"}} {
		neutral := exec.CommandContext(ctx, bin, args...)
		neutral.Dir, neutral.Env = root, testCommandEnv(root)
		if out, err := neutral.CombinedOutput(); err != nil {
			t.Fatalf("neutral command %v: %v %s", args, err, out)
		}
	}
	tokenBytes, _ := json.Marshal(map[string]string{"i": "fixture", "d": "example.test", "t": "Backend", "s": "synthetic-inspection-secret-0123456789", "a": server.URL})
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	inspect := exec.CommandContext(ctx, bin, "team", "invite", "inspect", "--json")
	inspect.Dir, inspect.Env = root, testCommandEnv(root)
	inspect.Stdin = strings.NewReader(token)
	if out, err := inspect.CombinedOutput(); err != nil || !strings.Contains(string(out), `"controller"`) {
		t.Fatalf("controller inspect: %v %s", err, out)
	}
	refused := exec.CommandContext(ctx, bin, "--identity-home", home, "team", "invite", "inspect", "--json")
	refused.Dir, refused.Env = root, testCommandEnv(root)
	refused.Stdin = strings.NewReader(token)
	if out, err := refused.CombinedOutput(); err == nil {
		t.Fatalf("external inspect should remain refused: %s", out)
	}
	if attempts.Load() != 0 || !reflect.DeepEqual(fileDigestsForTest(t, home), before) {
		t.Fatal("neutral command or controller inspection performed renewal network/state activity")
	}
	first := run("mail", "inbox")
	if attempts.Load() != 1 || !strings.Contains(first, "assertion renewal failed") {
		t.Fatalf("first attempt=%d output=%s", attempts.Load(), first)
	}
	second := run("mail", "inbox")
	if attempts.Load() != 1 || strings.Contains(second, "Warning:") {
		t.Fatalf("second attempt=%d output=%s", attempts.Load(), second)
	}
	backdate := func() {
		t.Helper()
		saved, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if saved.ActiveRecord().LastRenewalAttempt == "" {
			t.Fatal("failure backoff was not persisted")
		}
		saved.ActiveRecord().LastRenewalAttempt = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
		if err := awconfig.SaveEncryptionKeyStateTo(statePath, saved); err != nil {
			t.Fatal(err)
		}
	}
	backdate()
	retry := run("mail", "inbox")
	if attempts.Load() != 2 || !strings.Contains(retry, "assertion renewal failed") {
		t.Fatalf("expired backoff attempt=%d output=%s", attempts.Load(), retry)
	}
	backdate()
	accept.Store(true)
	success := run("mail", "inbox")
	if attempts.Load() != 3 || strings.Contains(success, "Warning:") {
		t.Fatalf("successful retry attempt=%d output=%s", attempts.Load(), success)
	}
	saved, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ActiveRecord().LastRenewalAttempt != "" {
		t.Fatal("successful renewal retained backoff")
	}
}

func TestEncryptionRenewalSerializesConcurrentRotation(t *testing.T) {
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := awid.GenerateKeypair()
	did := awid.ComputeDIDKey(pub)
	publications := make(chan *awid.EncryptionKeyAssertion, 2)
	releaseRenewal := make(chan struct{})
	var requests atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if requests.Add(1) == 1 {
			<-releaseRenewal
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"encryption_key": a})
	}))
	// Release the request before server cleanup even when an assertion fails.
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRenewal) }) }
	defer release()
	writeMessagingPrincipalForTest(t, root, server.URL, "alice", did, key)
	home := filepath.Join(root, ".aw")
	old := installMailReadEncryptionKeyForTest(t, root, home, did, key)
	statePath := filepath.Join(home, "encryption.yaml")
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		t.Fatal(err)
	}
	record := state.ActiveRecord()
	old.CreatedAt = time.Now().Add(-80 * 24 * time.Hour).UTC().Format(time.RFC3339)
	old.NotBefore = old.CreatedAt
	old.ExpiresAt = time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := awid.SignEncryptionKeyAssertion(old, key); err != nil {
		t.Fatal(err)
	}
	if err := saveEncryptionAssertion(filepath.Join(home, record.AssertionPath), old); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	renewalDone := make(chan error, 1)
	go func() {
		renewalDone <- renewIdentityEncryptionAssertion(ctx, root, explicitEncryptionKeyIdentityHome(home))
	}()
	select {
	case renewed := <-publications:
		if renewed.EncryptionKeyID != old.EncryptionKeyID {
			t.Fatal("renewal rotated")
		}
	case <-ctx.Done():
		t.Fatal("renewal never reached publication")
	}
	rotationStarted := make(chan struct{})
	rotationDone := make(chan error, 1)
	go func() {
		close(rotationStarted)
		_, err := setupOrRotateIdentityEncryptionKeyForDir(ctx, root, true, explicitEncryptionKeyIdentityHome(home))
		rotationDone <- err
	}()
	<-rotationStarted
	select {
	case <-publications:
		t.Fatal("rotation published while renewal still holds the keyring lock")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-renewalDone; err != nil {
		t.Fatal(err)
	}
	if err := <-rotationDone; err != nil {
		t.Fatal(err)
	}
	rotated := <-publications
	if rotated.EncryptionKeyID == old.EncryptionKeyID || rotated.PreviousEncryptionKeyID == nil || *rotated.PreviousEncryptionKeyID != old.EncryptionKeyID {
		t.Fatal("rotation lost previous key binding")
	}
	state, err = awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveKeyID != rotated.EncryptionKeyID || len(state.Keys) != 2 {
		t.Fatalf("renewal overwrote rotation: %+v", state)
	}
	archived := state.RecordForKeyID(old.EncryptionKeyID)
	if archived == nil {
		t.Fatal("rotation lost archived key")
	}
	if _, err := validateEncryptionRecordPrivateKeyAt(root, home, archived); err != nil {
		t.Fatal(err)
	}
}
