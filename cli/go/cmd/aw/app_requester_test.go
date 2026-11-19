package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// vectorChain is an aweb.id-chain of the id-certificates vector's signed
// certificates, root first.
func vectorChain(t *testing.T, names ...string) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Certificates map[string]struct {
			Signed map[string]any `json:"signed"`
		} `json:"certificates"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	var certificates []any
	for _, name := range names {
		signed, ok := vectors.Certificates[name]
		if !ok {
			t.Fatalf("no vector certificate %s", name)
		}
		certificates = append(certificates, signed.Signed)
	}
	return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}
}

func TestADirectChildOfAHumanActsForThatHuman(t *testing.T) {
	holder, err := directHumanParent(vectorChain(t, "alice", "coordinator"))
	if err != nil {
		t.Fatal(err)
	}
	if holder != "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w" {
		t.Fatalf("holder %q", holder)
	}
}

func TestOnlyADirectChildOfAHumanIsARequester(t *testing.T) {
	for name, chain := range map[string][]string{
		"a grandchild":     {"alice", "coordinator", "seat"},
		"a namespace root": {"root-agent"},
		"the human itself": {"alice"},
		"an empty chain":   {},
	} {
		if _, err := directHumanParent(vectorChain(t, chain...)); errorCodeOf(err) != "requester_missing" {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if _, err := directHumanParent(nil); errorCodeOf(err) != "requester_missing" {
		t.Errorf("no chain: err %v", err)
	}
}

func identityWithChain(t *testing.T, chain map[string]any) *localSigningIdentity {
	t.Helper()
	dir := t.TempDir()
	if chain != nil {
		if err := awconfig.SaveInstalledIDChain(dir, chain); err != nil {
			t.Fatal(err)
		}
	}
	return &localSigningIdentity{StableID: "did:aw:requester", SigningKeyPath: filepath.Join(dir, "signing.key")}
}

func TestAnAgentUnderAHumanStartsForThatHumanAndSendsItsChain(t *testing.T) {
	old := activeHuman
	activeHuman = nil
	t.Cleanup(func() { activeHuman = old })
	holder, header, err := holderFor(identityWithChain(t, vectorChain(t, "alice", "coordinator")))
	if err != nil {
		t.Fatal(err)
	}
	if holder != "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w" || header == "" {
		t.Fatalf("holder %q header %q", holder, header)
	}
}

func TestAGrandchildCannotStartForAHuman(t *testing.T) {
	old := activeHuman
	activeHuman = nil
	t.Cleanup(func() { activeHuman = old })
	if _, _, err := holderFor(identityWithChain(t, vectorChain(t, "alice", "coordinator", "seat"))); errorCodeOf(err) != "requester_missing" {
		t.Fatalf("err %v", err)
	}
}

func TestAnIdentityWithNoChainOrAHumanLeafStartsForItself(t *testing.T) {
	old := activeHuman
	activeHuman = nil
	t.Cleanup(func() { activeHuman = old })
	for name, chain := range map[string]map[string]any{"no chain": nil, "a human leaf": vectorChain(t, "alice")} {
		holder, header, err := holderFor(identityWithChain(t, chain))
		if err != nil || holder != "did:aw:requester" || header != "" {
			t.Errorf("%s: holder %q header %q err %v", name, holder, header, err)
		}
	}
}
