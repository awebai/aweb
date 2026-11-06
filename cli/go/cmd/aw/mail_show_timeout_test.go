package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The Docker regression exercises publicly provisioned identities and real
// grant admission/storage. This focused test drives the actual mail-show
// command and Unix custody to distinguish its caller context from API budgets.
func TestMailShowPerStepBudgetAndCallerCancellation(t *testing.T) {
	for _, scenario := range []string{"independent_steps", "cancel_later_unwrap", "deadline_later_unwrap"} {
		t.Run(scenario, func(t *testing.T) {
			resetCustodyClientGlobals(t)
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			setGrantTestEnv(t, root)
			t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")
			t.Setenv("AWEB_HTTP_TIMEOUT", "250ms")
			if scenario != "independent_steps" {
				t.Setenv("AWEB_HTTP_TIMEOUT", "2s")
			}
			_, residentKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			did := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
			stable := awid.ComputeStableID(residentKey.Public().(ed25519.PublicKey))
			private, public, err := awid.GenerateX25519Keypair()
			if err != nil {
				t.Fatal(err)
			}
			assertion, err := awid.BuildEncryptionKeyAssertion(residentKey, did, stable, public, "", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			const conversation = "66666666-6666-4666-8666-666666666666"
			var messages awid.InboxResponse
			envelopes := map[string]*awid.E2EEMessageEnvelope{}
			for i := range 4 {
				id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i)
				envelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
					Sender:     awid.E2EESenderKey{DID: did, StableID: stable, TeamID: "backend:acme.com", SigningKey: residentKey, EncryptionKey: assertion},
					Recipients: []awid.E2EERecipientKey{{DID: did, StableID: stable, EncryptionKey: assertion}},
					Subject:    "history", Body: fmt.Sprintf("body-%d", i), MessageID: id, ConversationID: conversation,
				})
				if err != nil {
					t.Fatal(err)
				}
				envelopes[id] = envelope
				messages.Messages = append(messages.Messages, awid.InboxMessage{MessageID: id, ConversationID: conversation,
					FromDID: did, FromStableID: stable, ToDID: did, ContentMode: awid.ContentModeEncryptedV2,
					MessageVersion: awid.E2EEMessageVersion, Encrypted: envelope})
			}
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/v1/messages/conversations/"+conversation {
					_ = json.NewEncoder(w).Encode(messages)
					return
				}
				http.NotFound(w, r)
			}))
			home := filepath.Join(root, "grant")
			_, state := writeGrantHomeForTest(t, home, server.URL)
			state.Subject.DIDKey, state.Subject.DIDAW = did, stable
			state.GrantID = "11111111-1111-4111-8111-111111111111"
			// Keep sockets short even under the native runner's long TMPDIR.
			sockets, err := os.MkdirTemp("/tmp", "aw-mail-budget-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(sockets) })
			sockets, err = filepath.EvalSymlinks(sockets)
			if err != nil {
				t.Fatal(err)
			}
			state.Custody.SocketPath = filepath.Join(sockets, "custody.sock")
			if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(home), state); err != nil {
				t.Fatal(err)
			}
			t.Setenv(awconfig.IdentityHomeEnv, home)
			sessionKey, err := awid.LoadSigningKey(awconfig.GrantHomeSigningKeyPath(home))
			if err != nil {
				t.Fatal(err)
			}
			svc := testCustodyService(t, residentKey, sessionKey)
			svc.socketPath, svc.identity.StableID = state.Custody.SocketPath, stable
			svc.e2eeAssertion, svc.e2eePrivateKey = assertion, private
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			svc.readStoredEnvelope = func(ctx context.Context, kind, id, thread string) (*awid.E2EEMessageEnvelope, error) {
				count := calls.Add(1)
				if scenario == "cancel_later_unwrap" && count == 3 {
					cancel()
				}
				delay := 120 * time.Millisecond
				if scenario == "deadline_later_unwrap" {
					delay = 200 * time.Millisecond
				}
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
				}
				return envelopes[id], nil
			}
			serviceContext, stop := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- svc.serve(serviceContext) }()
			t.Cleanup(func() { stop(); <-done })
			deadline := time.Now().Add(time.Second)
			for {
				if _, err := os.Stat(svc.socketPath); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("custody socket did not start")
				}
				time.Sleep(time.Millisecond)
			}
			if scenario == "deadline_later_unwrap" {
				var stopDeadline context.CancelFunc
				caller, stopDeadline = context.WithTimeout(caller, 500*time.Millisecond)
				defer stopDeadline()
			}
			oldConversation, oldMessage, oldJSON, oldLimit := mailShowConversationID, mailShowMessageID, jsonFlag, mailShowLimit
			oldWritten := commandStdout.written
			mailShowConversationID, mailShowMessageID, jsonFlag, mailShowLimit = conversation, "", true, 500
			t.Cleanup(func() {
				mailShowConversationID, mailShowMessageID, jsonFlag, mailShowLimit = oldConversation, oldMessage, oldJSON, oldLimit
				commandStdout.written = oldWritten
			})
			command := &cobra.Command{}
			command.SetContext(caller)
			output, err := os.CreateTemp(root, "result-*.json")
			if err != nil {
				t.Fatal(err)
			}
			stdout := os.Stdout
			t.Cleanup(func() { os.Stdout = stdout })
			os.Stdout = output
			started := time.Now()
			err = mailShowCmd.RunE(command, nil)
			elapsed := time.Since(started)
			os.Stdout = stdout
			_ = output.Close()
			body, readErr := os.ReadFile(output.Name())
			if readErr != nil {
				t.Fatal(readErr)
			}
			if scenario == "independent_steps" {
				if err != nil || calls.Load() != 4 || elapsed < 400*time.Millisecond {
					t.Fatalf("healthy steps must outlive one API budget: calls=%d elapsed=%s err=%v", calls.Load(), elapsed, err)
				}
				var result awid.InboxResponse
				if err := json.Unmarshal(body, &result); err != nil || len(result.Messages) != 4 {
					t.Fatalf("missing complete result: %s, %v", body, err)
				}
			} else {
				if err == nil || calls.Load() != 3 || elapsed > time.Second {
					t.Fatalf("caller must stop during the third unwrap: calls=%d elapsed=%s err=%v", calls.Load(), elapsed, err)
				}
				want := "context canceled"
				if scenario == "deadline_later_unwrap" {
					want = "context deadline exceeded"
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("lost caller cancellation: %v", err)
				}
				if len(body) != 0 {
					t.Fatalf("caller cancellation printed a partial-success page: %s", body)
				}
			}
		})
	}
}
