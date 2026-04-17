package main

import "testing"

func TestResolveMailTargetKeepsTildeTargetAsAlias(t *testing.T) {
	oldTo, oldToDID, oldToAddress := mailSendTo, mailSendToDID, mailSendToAddress
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
	})

	mailSendTo = "ops~alice"
	mailSendToDID = ""
	mailSendToAddress = ""

	kind, value, err := resolveMailTarget()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "alias" {
		t.Fatalf("kind=%q, want alias", kind)
	}
	if value != "ops~alice" {
		t.Fatalf("value=%q, want ops~alice", value)
	}
}
