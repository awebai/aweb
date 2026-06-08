package awid

import (
	"encoding/json"
	"testing"
)

func TestA2APublicationConflictCodesMatchSharedVector(t *testing.T) {
	data := readDocsVector(t, "a2a-awid-publication-v1.json")
	var vector struct {
		ConflictCodes []string `json:"conflict_codes"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.ConflictCodes) != len(A2APublicationConflictCodes) {
		t.Fatalf("codes len=%d want %d", len(A2APublicationConflictCodes), len(vector.ConflictCodes))
	}
	for i, got := range A2APublicationConflictCodes {
		if want := vector.ConflictCodes[i]; got != want {
			t.Fatalf("code[%d]: got %q want %q", i, got, want)
		}
	}
}

func TestA2APublicationCanonicalHelpersMatchSharedVector(t *testing.T) {
	data := readDocsVector(t, "a2a-awid-publication-v1.json")
	var vector struct {
		Publication struct {
			Payload   map[string]any `json:"payload"`
			Canonical string         `json:"canonical"`
			Signature string         `json:"signature"`
		} `json:"publication"`
		Delegation struct {
			Payload   map[string]any `json:"payload"`
			Canonical string         `json:"canonical"`
			Signature string         `json:"signature"`
		} `json:"delegation"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	delegationCanonical, err := A2ADelegationCanonical(A2ADelegationFields{
		Operation:                stringVectorField(vector.Delegation.Payload, "operation"),
		DelegationID:             stringVectorField(vector.Delegation.Payload, "delegation_id"),
		DelegatorDIDAW:           stringVectorField(vector.Delegation.Payload, "delegator_did_aw"),
		DelegatorCurrentDIDKey:   stringVectorField(vector.Delegation.Payload, "delegator_current_did_key"),
		DelegatedGatewayIdentity: stringVectorField(vector.Delegation.Payload, "delegated_gateway_identity"),
		Address:                  stringVectorField(vector.Delegation.Payload, "address"),
		RouteID:                  stringVectorField(vector.Delegation.Payload, "route_id"),
		CardURL:                  stringVectorField(vector.Delegation.Payload, "card_url"),
		RPCURL:                   stringVectorField(vector.Delegation.Payload, "rpc_url"),
		AllowedOperations:        stringSliceVectorField(t, vector.Delegation.Payload, "allowed_operations"),
		CardDigestAlg:            stringVectorField(vector.Delegation.Payload, "card_digest_alg"),
		CardDigest:               stringVectorField(vector.Delegation.Payload, "card_digest"),
		CustodyMode:              stringVectorField(vector.Delegation.Payload, "custody_mode"),
		AuthoritySource:          stringVectorField(vector.Delegation.Payload, "authority_source"),
		SignerDID:                stringVectorField(vector.Delegation.Payload, "signer_did"),
		SignerKID:                stringVectorField(vector.Delegation.Payload, "signer_kid"),
		IssuedAt:                 stringVectorField(vector.Delegation.Payload, "issued_at"),
		ExpiresAt:                stringVectorField(vector.Delegation.Payload, "expires_at"),
		Status:                   stringVectorField(vector.Delegation.Payload, "status"),
		RegistryURL:              stringVectorField(vector.Delegation.Payload, "registry_url"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if delegationCanonical != vector.Delegation.Canonical {
		t.Fatalf("delegation canonical:\n got: %s\nwant: %s", delegationCanonical, vector.Delegation.Canonical)
	}
	delegationDigest, err := A2ASignedAssertionDigest(delegationCanonical, vector.Delegation.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if got := stringVectorField(vector.Publication.Payload, "delegation_digest"); got != delegationDigest {
		t.Fatalf("publication delegation_digest=%s want %s", got, delegationDigest)
	}

	publicationCanonical, err := A2APublicationCanonical(A2APublicationFields{
		Operation:        stringVectorField(vector.Publication.Payload, "operation"),
		AssertionID:      stringVectorField(vector.Publication.Payload, "assertion_id"),
		Address:          stringVectorField(vector.Publication.Payload, "address"),
		DIDAW:            stringVectorField(vector.Publication.Payload, "did_aw"),
		CurrentDIDKey:    stringVectorField(vector.Publication.Payload, "current_did_key"),
		SignerDID:        stringVectorField(vector.Publication.Payload, "signer_did"),
		SignerKID:        stringVectorField(vector.Publication.Payload, "signer_kid"),
		CardURL:          stringVectorField(vector.Publication.Payload, "card_url"),
		RPCURL:           stringVectorField(vector.Publication.Payload, "rpc_url"),
		RouteID:          stringVectorField(vector.Publication.Payload, "route_id"),
		GatewayIdentity:  stringVectorField(vector.Publication.Payload, "gateway_identity"),
		DelegationID:     stringVectorField(vector.Publication.Payload, "delegation_id"),
		DelegationDigest: stringVectorField(vector.Publication.Payload, "delegation_digest"),
		CardDigestAlg:    stringVectorField(vector.Publication.Payload, "card_digest_alg"),
		CardDigest:       stringVectorField(vector.Publication.Payload, "card_digest"),
		CardRevision:     stringVectorField(vector.Publication.Payload, "card_revision"),
		DefaultForHost:   boolVectorField(vector.Publication.Payload, "default_for_host"),
		Status:           stringVectorField(vector.Publication.Payload, "status"),
		PublishedAt:      stringVectorField(vector.Publication.Payload, "published_at"),
		ExpiresAt:        stringVectorField(vector.Publication.Payload, "expires_at"),
		RegistryURL:      stringVectorField(vector.Publication.Payload, "registry_url"),
		IdentityCustody:  stringVectorField(vector.Publication.Payload, "identity_custody"),
		AuthoritySource:  stringVectorField(vector.Publication.Payload, "authority_source"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if publicationCanonical != vector.Publication.Canonical {
		t.Fatalf("publication canonical:\n got: %s\nwant: %s", publicationCanonical, vector.Publication.Canonical)
	}
}

func stringVectorField(value map[string]any, key string) string {
	got, _ := value[key].(string)
	return got
}

func boolVectorField(value map[string]any, key string) bool {
	got, _ := value[key].(bool)
	return got
}

func stringSliceVectorField(t *testing.T, value map[string]any, key string) []string {
	t.Helper()
	raw, ok := value[key].([]any)
	if !ok {
		t.Fatalf("field %s is not []any", key)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("field %s contains non-string %#v", key, item)
		}
		out = append(out, text)
	}
	return out
}
