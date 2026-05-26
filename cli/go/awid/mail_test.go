package awid

import "testing"

func TestMailConversationTargetPrefersAddressForE2EE(t *testing.T) {
	t.Parallel()

	client := &Client{
		stableID: "did:aw:self",
		did:      "did:key:self",
		address:  "alpha.test.local/alice",
	}
	item := ConversationItem{
		ConversationID:       "conv-1",
		ParticipantDIDs:      []string{"did:aw:self", "did:aw:other"},
		ParticipantAddresses: []string{"alpha.test.local/alice", "beta.test.local/bob"},
	}

	legacy := client.mailConversationItemTarget(item, false)
	if legacy.kind != "did" || legacy.value != "did:aw:other" {
		t.Fatalf("legacy target=(%q,%q), want did/did:aw:other", legacy.kind, legacy.value)
	}

	encrypted := client.mailConversationItemTarget(item, true)
	if encrypted.kind != "address" || encrypted.value != "beta.test.local/bob" {
		t.Fatalf("encrypted target=(%q,%q), want address/beta.test.local/bob", encrypted.kind, encrypted.value)
	}
}

func TestMailInboxTargetPrefersAddressForE2EE(t *testing.T) {
	t.Parallel()

	client := &Client{
		stableID: "did:aw:self",
		did:      "did:key:self",
		address:  "alpha.test.local/alice",
	}
	messages := []InboxMessage{{
		ConversationID: "conv-1",
		FromStableID:   "did:aw:self",
		FromDID:        "did:key:self",
		FromAddress:    "alpha.test.local/alice",
		ToStableID:     "did:aw:other",
		ToDID:          "did:key:other",
		ToAddress:      "beta.test.local/bob",
	}}

	legacy := client.mailInboxTarget(messages, false)
	if legacy.kind != "did" || legacy.value != "did:aw:other" {
		t.Fatalf("legacy target=(%q,%q), want did/did:aw:other", legacy.kind, legacy.value)
	}

	encrypted := client.mailInboxTarget(messages, true)
	if encrypted.kind != "address" || encrypted.value != "beta.test.local/bob" {
		t.Fatalf("encrypted target=(%q,%q), want address/beta.test.local/bob", encrypted.kind, encrypted.value)
	}
}
