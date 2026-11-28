package main

import (
	"encoding/json"
	"testing"
)

// docs/mail-and-chat.md: a fresh CLI send defaults to server-readable
// plaintext, and --e2ee asks for encryption. Through the real binary, server
// and registry, each intent arrives as the content mode it asked for.
func TestRealServerMailSendsPlaintextByDefaultAndEncryptsOnRequest(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob")

	world.requireCommand(t, alice.Home, "mail", "send", "--to", "bob", "--subject", "default-intent", "--body", "plain body")
	world.requireCommand(t, alice.Home, "mail", "send", "--e2ee", "--to", "bob", "--subject", "e2ee-intent", "--body", "sealed body")

	var inbox struct {
		Messages []struct {
			Subject     string `json:"subject"`
			Body        string `json:"body"`
			ContentMode string `json:"content_mode"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(world.requireCommand(t, bob.Home, "mail", "inbox")), &inbox); err != nil {
		t.Fatal(err)
	}
	got := map[string][2]string{}
	for _, message := range inbox.Messages {
		got[message.Subject] = [2]string{message.ContentMode, message.Body}
	}
	if got["default-intent"] != [2]string{"legacy_plaintext_v1", "plain body"} {
		t.Fatalf("a send with no encryption flag arrived as %v", got["default-intent"])
	}
	if got["e2ee-intent"] != [2]string{"encrypted_v2", "sealed body"} {
		t.Fatalf("an --e2ee send arrived as %v", got["e2ee-intent"])
	}
}
