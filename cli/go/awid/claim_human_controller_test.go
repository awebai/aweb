package awid

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClaimHumanCarriesTheSharedControllerArtifact(t *testing.T) {
	artifact, err := ParseUnownedTeamClaim(loadTeamControlVectors(t).ClaimCases[0].Artifact)
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimHumanRequest{Username: artifact.Request.Username, Email: artifact.Request.Email, DIDKey: "did:key:member", ControllerClaim: &artifact}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Username string          `json:"username"`
		Email    string          `json:"email"`
		DIDKey   string          `json:"did_key"`
		Claim    json.RawMessage `json:"controller_claim"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	carried, err := ParseUnownedTeamClaim(envelope.Claim)
	if err != nil || carried != artifact {
		t.Fatalf("controller artifact changed in the member carrier: %v", err)
	}
	if envelope.Username != artifact.Request.Username || envelope.Email != artifact.Request.Email || envelope.DIDKey != request.DIDKey {
		t.Fatal("controller carrier changed the member's request fields")
	}
	request.ControllerClaim = nil
	withoutClaim, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(withoutClaim), "controller_claim") {
		t.Fatal("ordinary member claim gained a controller field")
	}
}

func TestControllerArtifactDoesNotReplaceMemberTransportAuthentication(t *testing.T) {
	artifact, err := ParseUnownedTeamClaim(loadTeamControlVectors(t).ClaimCases[0].Artifact)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{}
	_, err = client.ClaimHuman(t.Context(), &ClaimHumanRequest{Username: artifact.Request.Username, Email: artifact.Request.Email, DIDKey: "did:key:member", ControllerClaim: &artifact})
	if err == nil || !strings.Contains(err.Error(), "requires a signing key") {
		t.Fatalf("controller artifact bypassed member transport authentication: %v", err)
	}
}
