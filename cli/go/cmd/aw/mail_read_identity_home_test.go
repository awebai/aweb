package main

import (
	"bytes"
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

func TestMailReadsDecryptWithSelectedPrincipalIdentityHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principalRoot := filepath.Join(root, "principal")
	instanceRoot := filepath.Join(root, "instance")
	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowPub, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	shadowDID := awid.ComputeDIDKey(shadowPub)

	messageID := "11111111-1111-4111-8111-111111111163"
	conversationID := "22222222-2222-4222-8222-222222222263"
	var encryptedMessage awid.InboxMessage
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{encryptedMessage}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/"+messageID:
			_ = json.NewEncoder(w).Encode(encryptedMessage)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages/"+messageID+"/ack":
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: messageID, AcknowledgedAt: "2026-08-04T00:00:00Z"})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))

	writeMessagingPrincipalForTest(t, principalRoot, server.URL, "principal", principalDID, principalKey)
	writeMessagingPrincipalForTest(t, instanceRoot, server.URL, "shadow", shadowDID, shadowKey)
	principalHome := filepath.Join(principalRoot, ".aw")
	instanceHome := filepath.Join(instanceRoot, ".aw")
	principalAssertion := installMailReadEncryptionKeyForTest(t, instanceRoot, principalHome, principalDID, principalKey)
	shadowAssertion := installMailReadEncryptionKeyForTest(t, instanceRoot, instanceHome, shadowDID, shadowKey)
	if principalHome == instanceHome || principalAssertion.EncryptionKeyID == shadowAssertion.EncryptionKeyID {
		t.Fatal("test requires distinct principal and ambient identity homes with distinct encryption keys")
	}

	remotePub, remoteKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, remoteEncryptionPub, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	remoteDID := awid.ComputeDIDKey(remotePub)
	remoteAssertion, err := awid.BuildEncryptionKeyAssertion(remoteKey, remoteDID, "", remoteEncryptionPub, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
		Sender: awid.E2EESenderKey{
			DID:           remoteDID,
			EncryptionKey: remoteAssertion,
			SigningKey:    remoteKey,
		},
		Recipients: []awid.E2EERecipientKey{{
			DID:           principalDID,
			EncryptionKey: principalAssertion,
		}},
		Subject:        "selected principal subject",
		Body:           "selected principal body",
		MessageID:      messageID,
		ConversationID: conversationID,
		CreatedAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	encryptedMessage = awid.InboxMessage{
		MessageID:      messageID,
		ConversationID: conversationID,
		FromAlias:      "remote",
		ToAlias:        "principal",
		FromDID:        remoteDID,
		ToDID:          principalDID,
		ContentMode:    awid.ContentModeEncryptedV2,
		MessageVersion: awid.E2EEMessageVersion,
		Encrypted:      envelope,
		Priority:       awid.PriorityNormal,
		CreatedAt:      envelope.CreatedAt,
	}

	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	commands := []struct {
		name string
		args []string
	}{
		{name: "inbox", args: []string{"mail", "inbox"}},
		{name: "show-without-team", args: []string{"mail", "show", "--message-id", messageID}},
		{name: "show-with-team", args: []string{"--team", "runtime:aweb.test", "mail", "show", "--message-id", messageID}},
	}
	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--identity-home", principalHome}, tc.args...)
			command := exec.CommandContext(ctx, bin, args...)
			command.Dir = instanceRoot
			command.Env = append(testCommandEnv(filepath.Join(root, "home")), awconfig.IdentityHomeEnv+"=")
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("mail read failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
			}
			for _, want := range []string{"selected principal subject", "selected principal body"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("mail read did not decrypt %q through selected principal\nstdout:\n%s\nstderr:\n%s", want, stdout.String(), stderr.String())
				}
			}
			if strings.Contains(stderr.String(), "decryption unavailable") {
				t.Fatalf("mail read reported unavailable decryption despite selected principal key:\n%s", stderr.String())
			}
		})
	}
}

func TestMailReadReportsSelectedEncryptionStatePathWhenDecryptionKeyIsUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	messageID := "11111111-1111-4111-8111-111111111164"
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/"+messageID:
			_ = json.NewEncoder(w).Encode(awid.InboxMessage{MessageID: messageID, Subject: "plaintext", Body: "still readable"})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	for _, tc := range []struct {
		name       string
		writeState bool
		wantReason string
	}{
		{name: "missing-state-file", wantReason: "no encryption key state"},
		{name: "no-active-record", writeState: true, wantReason: "no active encryption key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principalRoot := filepath.Join(root, tc.name, "principal")
			instanceRoot := filepath.Join(root, tc.name, "instance")
			principalPub, principalKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			shadowPub, shadowKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			principalDID := awid.ComputeDIDKey(principalPub)
			shadowDID := awid.ComputeDIDKey(shadowPub)
			writeMessagingPrincipalForTest(t, principalRoot, server.URL, "principal", principalDID, principalKey)
			writeMessagingPrincipalForTest(t, instanceRoot, server.URL, "shadow", shadowDID, shadowKey)
			principalHome := filepath.Join(principalRoot, ".aw")
			instanceHome := filepath.Join(instanceRoot, ".aw")
			installMailReadEncryptionKeyForTest(t, instanceRoot, instanceHome, shadowDID, shadowKey)
			statePath := filepath.Join(principalHome, "encryption.yaml")
			if tc.writeState {
				if err := awconfig.SaveEncryptionKeyStateTo(statePath, &awconfig.EncryptionKeyState{}); err != nil {
					t.Fatal(err)
				}
			}

			commands := []struct {
				name string
				args []string
			}{
				{name: "inbox", args: []string{"mail", "inbox"}},
				{name: "show-without-team", args: []string{"mail", "show", "--message-id", messageID}},
				{name: "show-with-team", args: []string{"--team", "runtime:aweb.test", "mail", "show", "--message-id", messageID}},
			}
			for _, commandCase := range commands {
				t.Run(commandCase.name, func(t *testing.T) {
					args := append([]string{"--identity-home", principalHome}, commandCase.args...)
					command := exec.CommandContext(ctx, bin, args...)
					command.Dir = instanceRoot
					command.Env = append(testCommandEnv(filepath.Join(root, "home")), awconfig.IdentityHomeEnv+"=")
					var stdout, stderr bytes.Buffer
					command.Stdout = &stdout
					command.Stderr = &stderr
					if err := command.Run(); err != nil {
						t.Fatalf("plaintext-capable mail read should remain available: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
					}
					for _, want := range []string{"decryption unavailable", tc.wantReason, statePath} {
						if !strings.Contains(strings.ToLower(stderr.String()), strings.ToLower(want)) {
							t.Fatalf("stderr missing %q for selected principal lookup:\n%s", want, stderr.String())
						}
					}
					if strings.Contains(stderr.String(), filepath.Join(instanceHome, "encryption.yaml")) {
						t.Fatalf("diagnostic reported ambient identity home instead of selected principal:\n%s", stderr.String())
					}
				})
			}
		})
	}
}

func installMailReadEncryptionKeyForTest(t *testing.T, workingDir, identityHome, did string, signingKey ed25519.PrivateKey) *awid.EncryptionKeyAssertion {
	t.Helper()
	identity := &awconfig.ResolvedIdentity{
		WorkingDir:           workingDir,
		IdentityHome:         identityHome,
		ExternalIdentityHome: true,
		DID:                  did,
		Custody:              awid.CustodySelf,
		IdentityScope:        awid.IdentityModeLocal,
		Lifetime:             awid.LifetimeEphemeral,
	}
	record, assertion, err := createLocalEncryptionKeyRecord(identity, signingKey, "")
	if err != nil {
		t.Fatal(err)
	}
	statePath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "encryption.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveEncryptionKeyStateTo(statePath, &awconfig.EncryptionKeyState{
		ActiveKeyID: record.KeyID,
		Keys:        []awconfig.EncryptionKeyRecord{*record},
	}); err != nil {
		t.Fatal(err)
	}
	return assertion
}
