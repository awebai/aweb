package awid

import (
	"context"
	"testing"
)

// The child has its own controller/epochs; the found TXT belongs to its
// ancestor. Use an unenrolled subject so no certificate's signature can hide
// the distinction between unavailable authority and an unregistered ID.
func TestIDNamespaceDelegationBinding(t *testing.T) {
	for _, mutation := range []string{"valid", "missing", "wrong-parent-key", "wrong-child-key", "sibling", "self", "label-boundary", "wrong-dns-name", "extra", "no-anchor", "exact-wins", "exact-mismatch"} {
		t.Run(mutation, func(t *testing.T) {
			v := loadStatusVectors(t)
			status := v.Statuses["normal"]
			child := "child.example.com"
			childKey := openEpochKey(status)
			parentKey := "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2"
			subject := IDChainSubject{ID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", DIDKey: childKey}
			delegation := map[string]any{"parent_domain": "example.com", "parent_controller_key": parentKey, "controller_key": childKey}
			status["domain"], status["identities"], status["missing"] = child, []any{}, []any{subject.ID}
			namespace := status["namespace"].(map[string]any)
			namespace["delegation"] = delegation
			authority := map[string]any{"domain": child, "dns_name": "_awid.example.com", "inherited": true, "controller_key": parentKey}
			want := "evidence_unavailable"
			switch mutation {
			case "valid":
				want = "unregistered_identity"
			case "missing":
				delete(namespace, "delegation")
			case "wrong-parent-key":
				delegation["parent_controller_key"] = childKey
			case "wrong-child-key":
				delegation["controller_key"] = parentKey
			case "sibling":
				delegation["parent_domain"] = "other.example.com"
			case "self":
				delegation["parent_domain"] = child
			case "label-boundary":
				delegation["parent_domain"] = "ample.com"
			case "wrong-dns-name":
				authority["dns_name"] = "_awid.other.example.com"
			case "extra":
				delegation["extra"] = true
			case "no-anchor":
				authority["dns_name"], authority["controller_key"], authority["inherited"] = "", "", false
			case "exact-wins":
				authority["dns_name"], authority["controller_key"], authority["inherited"] = "_awid."+child, childKey, false
				delegation["parent_controller_key"] = childKey
				want = "unregistered_identity"
			case "exact-mismatch":
				authority["dns_name"], authority["inherited"] = "_awid."+child, false
			}
			age := 0.0
			got := VerifyIDChain(nil, subject, &IDChainEvidence{Status: status, NamespaceAuthority: authority, AgeSeconds: &age}, child)
			if got.Reason != want {
				t.Fatalf("got %+v want %s", got, want)
			}
		})
	}
}

func TestIDStatusClientDiscoversAncestorAndPrefersExact(t *testing.T) {
	child, parent := "child.example.com", "example.com"
	childKey := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	parentKey := "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2"
	resolver := staticTXTResolver{"_awid." + parent: {"awid=v1; controller=" + parentKey + ";"}}
	client := NewIDStatusClient(NewAWIDRegistryClient(nil, resolver), resolver)
	a, err := client.Authority(context.Background(), child)
	if err != nil || !a.Inherited || a.ControllerDID != parentKey || a.DNSName != "_awid."+parent {
		t.Fatalf("ancestor %+v %v", a, err)
	}
	resolver["_awid."+child] = []string{"awid=v1; controller=" + childKey + ";"}
	a, err = client.Authority(context.Background(), child)
	if err != nil || a.Inherited || a.ControllerDID != childKey || a.DNSName != "_awid."+child {
		t.Fatalf("exact %+v %v", a, err)
	}
}

func TestIDStatusClientNoTXTDoesNotUsePublicDefault(t *testing.T) {
	resolver := staticTXTResolver{}
	client := NewIDStatusClient(NewAWIDRegistryClient(nil, resolver), resolver)
	client.Route = func(context.Context, string) (string, error) {
		t.Error("unanchored status must not use the public registry fallback")
		return "http://127.0.0.1:1", nil
	}
	subject := IDChainSubject{ID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"}
	evidence := client.IDChainEvidence(context.Background(), nil, subject, "child.example.com")
	if got := VerifyIDChain(nil, subject, evidence, "child.example.com"); got.Reason != "evidence_unavailable" || evidence.AgeSeconds != nil {
		t.Fatalf("got %+v evidence %+v", got, evidence)
	}
}
