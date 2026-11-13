package awid

import (
	"fmt"
	"reflect"
	"testing"
)

// statusSigned is a signed certificate of id in example.com under parent.
func statusSigned(id string, parent map[string]any, issuedAt string) map[string]any {
	return map[string]any{
		"certificate": map[string]any{"v": 1, "type": "aweb.id-certificate", "id": id, "domain": "example.com", "parent": parent,
			"kind": "human", "issuer_key": "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX", "issued_at": issuedAt},
		"signature": "c2ln",
	}
}

// statusRow is a status identity whose current certificate is current among
// its revisions.
func statusRow(t *testing.T, id string, current map[string]any, revisions ...map[string]any) map[string]any {
	t.Helper()
	head, err := IDCertificateID(current["certificate"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	certificates := []any{}
	for _, revision := range revisions {
		certificates = append(certificates, map[string]any{"signed": revision})
	}
	return map[string]any{"id": id, "current_certificate_id": head, "certificates": certificates}
}

var namespaceParent = map[string]any{"kind": "namespace", "id": "example.com"}

func TestTheRegisteredChainFollowsEachCurrentCertificateToTheNamespace(t *testing.T) {
	g := statusSigned("did:aw:G", namespaceParent, "2026-01-01T00:00:00Z")
	gOld := statusSigned("did:aw:G", namespaceParent, "2025-01-01T00:00:00Z")
	h := statusSigned("did:aw:H", map[string]any{"kind": "identity", "id": "did:aw:G"}, "2026-02-01T00:00:00Z")
	status := map[string]any{"identities": []any{statusRow(t, "did:aw:H", h, h), statusRow(t, "did:aw:G", g, gOld, g)}}
	chain, err := RegisteredIDChain(status, "did:aw:H")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{g, h}}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("chain %v", chain)
	}

	single, err := RegisteredIDChain(map[string]any{"identities": []any{statusRow(t, "did:aw:G", g, g)}}, "did:aw:G")
	if err != nil || !reflect.DeepEqual(single["certificates"], []any{g}) {
		t.Fatalf("single %v err %v", single, err)
	}
}

func TestARegisteredChainWithAMissingOrUncurrentLinkIsNotBuilt(t *testing.T) {
	g := statusSigned("did:aw:G", namespaceParent, "2026-01-01T00:00:00Z")
	gOld := statusSigned("did:aw:G", namespaceParent, "2025-01-01T00:00:00Z")
	h := statusSigned("did:aw:H", map[string]any{"kind": "identity", "id": "did:aw:G"}, "2026-02-01T00:00:00Z")
	loop := statusSigned("did:aw:L", map[string]any{"kind": "identity", "id": "did:aw:L"}, "2026-01-01T00:00:00Z")
	gCurrentAbsent := statusRow(t, "did:aw:G", g, gOld)
	for name, status := range map[string]map[string]any{
		"no row for the id":           {"identities": []any{statusRow(t, "did:aw:G", g, g)}},
		"no row for its parent":       {"identities": []any{statusRow(t, "did:aw:H", h, h)}},
		"parent's current not listed": {"identities": []any{statusRow(t, "did:aw:H", h, h), gCurrentAbsent}},
		"a parent loop":               {"identities": []any{statusRow(t, "did:aw:L", loop, loop)}},
		"two rows for one id":         {"identities": []any{statusRow(t, "did:aw:G", g, g), statusRow(t, "did:aw:G", g, g)}},
		"not a status":                {"identities": "none"},
	} {
		id := "did:aw:H"
		switch name {
		case "a parent loop":
			id = "did:aw:L"
		case "two rows for one id":
			id = "did:aw:G"
		}
		if chain, err := RegisteredIDChain(status, id); err == nil {
			t.Errorf("%s: built %v", name, chain)
		}
	}
}

func TestARegisteredChainDeeperThanTheMaximumIsNotBuilt(t *testing.T) {
	parent := namespaceParent
	var rows []any
	for i := 0; i <= IDChainMaxDepth; i++ {
		id := fmt.Sprintf("did:aw:D%d", i)
		signed := statusSigned(id, parent, "2026-01-01T00:00:00Z")
		rows = append(rows, statusRow(t, id, signed, signed))
		parent = map[string]any{"kind": "identity", "id": id}
	}
	if chain, err := RegisteredIDChain(map[string]any{"identities": rows}, fmt.Sprintf("did:aw:D%d", IDChainMaxDepth)); err == nil {
		t.Fatalf("built a chain of %d", len(chain["certificates"].([]any)))
	}
	if _, err := RegisteredIDChain(map[string]any{"identities": rows[:IDChainMaxDepth]}, fmt.Sprintf("did:aw:D%d", IDChainMaxDepth-1)); err != nil {
		t.Fatalf("the maximum depth: %v", err)
	}
}
