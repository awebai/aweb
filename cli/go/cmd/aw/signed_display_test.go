package main

import (
	"context"
	"crypto/ed25519"
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

func TestSignedDisplayBindingProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	home := t.TempDir()
	bin := filepath.Join(home, "aw")
	buildAwBinary(t, ctx, bin)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	// Empty addresses isolate signed-display integrity from registry/roster trust.
	for _, tampered := range []bool{false, true} {
		name := "matching"
		want := awid.Verified
		if tampered {
			name = "tampered"
			want = awid.Failed
		}
		t.Run(name, func(t *testing.T) {
			messages := make(map[string]awid.InboxMessage)
			for _, kind := range []string{"mail", "chat"} {
				env := &awid.MessageEnvelope{Type: kind, FromDID: did, ToDID: did, Body: "signed body", Subject: "subject", MessageID: "message", ConversationID: "conversation"}
				sig, _ := awid.SignMessage(key, env)
				m := awid.InboxMessage{FromDID: did, ToDID: did, Body: env.Body, Subject: env.Subject, MessageID: env.MessageID, ConversationID: env.ConversationID, SignedPayload: awid.CanonicalJSON(env), Signature: sig}
				if tampered {
					m.Body = "tampered displayed body"
				}
				messages[kind] = m
			}
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/messages/message":
					_ = json.NewEncoder(w).Encode(messages["mail"])
				case r.URL.Path == "/v1/messages/inbox":
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{messages["mail"]}})
				case r.URL.Path == "/v1/chat/sessions/conversation/messages":
					_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{messages["chat"]}})
				case strings.HasSuffix(r.URL.Path, "/ack"), r.URL.Path == "/v1/agents/heartbeat":
					_ = json.NewEncoder(w).Encode(map[string]any{})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", 500)
				}
			}))
			wd := t.TempDir()
			if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(wd), key); err != nil {
				t.Fatal(err)
			}
			writeDefaultWorkspaceBindingForTest(t, wd, server.URL)
			for _, args := range [][]string{{"mail", "show", "--message-id", "message", "--json"}, {"mail", "inbox", "--show-all", "--json"}, {"chat", "history", "--session-id", "conversation", "--json"}} {
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = wd
				cmd.Env = append(testCommandEnv(wd), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AW_NO_UPDATE_CHECK=1")
				output, err := cmd.Output()
				if err != nil {
					t.Fatalf("%v: %v\n%s", args, err, output)
				}
				var result struct {
					Messages []struct {
						Body         string                  `json:"body"`
						Verification awid.VerificationStatus `json:"verification_status"`
					}
				}
				if err := json.Unmarshal(output, &result); err != nil {
					t.Fatalf("%v: %v\n%s", args, err, output)
				}
				if len(result.Messages) != 1 {
					t.Fatalf("%v: %s", args, output)
				}
				got := result.Messages[0]
				if got.Verification != want || got.Body != messages["mail"].Body {
					t.Errorf("%v: status/body=%+v want=%s/%s", args, got, want, messages["mail"].Body)
				}
			}
		})
	}
}

func TestOwnSentLegacyMailDisplayProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	home := t.TempDir()
	bin := filepath.Join(home, "aw")
	buildAwBinary(t, ctx, bin)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	// Empty addresses isolate signed-display integrity from registry/roster trust.
	for _, tampered := range []bool{false, true} {
		name := "matching"
		want := awid.Verified
		if tampered {
			name = "tampered"
			want = awid.Failed
		}
		t.Run(name, func(t *testing.T) {
			messages := make(map[string]awid.InboxMessage)
			for _, kind := range []string{"mail"} {
				env := &awid.MessageEnvelope{Type: kind, FromDID: did, ToDID: "", Body: "signed body", Subject: "subject", MessageID: "message", ConversationID: "conversation"}
				sig, _ := awid.SignMessage(key, env)
				m := awid.InboxMessage{FromDID: did, ToDID: "did:key:recipient", Body: env.Body, Subject: env.Subject, MessageID: env.MessageID, ConversationID: env.ConversationID, SignedPayload: awid.CanonicalJSON(env), Signature: sig}
				if tampered {
					m.Body = "tampered displayed body"
				}
				messages[kind] = m
			}
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/messages/message":
					_ = json.NewEncoder(w).Encode(messages["mail"])
				case r.URL.Path == "/v1/messages/conversations/conversation":
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{messages["mail"]}})
				case strings.HasSuffix(r.URL.Path, "/ack"), r.URL.Path == "/v1/agents/heartbeat":
					_ = json.NewEncoder(w).Encode(map[string]any{})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", 500)
				}
			}))
			wd := t.TempDir()
			if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(wd), key); err != nil {
				t.Fatal(err)
			}
			writeDefaultWorkspaceBindingForTest(t, wd, server.URL)
			for _, args := range [][]string{{"mail", "show", "--message-id", "message", "--json"}, {"mail", "show", "--conversation-id", "conversation", "--json"}} {
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = wd
				cmd.Env = append(testCommandEnv(wd), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AW_NO_UPDATE_CHECK=1")
				output, err := cmd.Output()
				if err != nil {
					t.Fatalf("%v: %v\n%s", args, err, output)
				}
				var result struct {
					Messages []struct {
						Body         string                  `json:"body"`
						Verification awid.VerificationStatus `json:"verification_status"`
					}
				}
				if err := json.Unmarshal(output, &result); err != nil {
					t.Fatalf("%v: %v\n%s", args, err, output)
				}
				if len(result.Messages) != 1 {
					t.Fatalf("%v: %s", args, output)
				}
				got := result.Messages[0]
				if got.Verification != want || got.Body != messages["mail"].Body {
					t.Errorf("%v: status/body=%+v want=%s/%s", args, got, want, messages["mail"].Body)
				}
			}
		})
	}
}
