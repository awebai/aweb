package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestHostedInviteRecoveryRequiresOneCompleteJSONValue(t *testing.T) {
	for _, sample := range []struct {
		name, suffix string
		valid        bool
	}{
		{"whitespace", " \n\t", true},
		{"second value", ` {"another_attempt":true}`, false},
		{"trailing garbage", " trailing", false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hosted-invite-creation.json")
			state := &hostedInviteCreation{
				Tree:      &hostedIDTreeRecovery{RequestID: "11111111-1111-4111-8111-111111111111"},
				TokenHash: "retained-hash", DIDKey: "retained-member",
			}
			if err := state.save(path); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, sample.suffix...)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadHostedInviteCreation(path)
			if sample.valid {
				if err != nil || loaded == nil || loaded.TokenHash != state.TokenHash || loaded.DIDKey != state.DIDKey || loaded.Tree.RequestID != state.Tree.RequestID {
					t.Fatalf("whitespace changed the retained request: %v", err)
				}
			} else if err == nil || loaded != nil {
				t.Fatal("incomplete or multiple JSON values accepted as a retained attempt")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, after) {
				t.Fatal("inspection rewrote the retained attempt")
			}
		})
	}
}
