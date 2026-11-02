package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreationRegistrationRequestKeepsRequiredNullMembers(t *testing.T) {
	for _, raw := range []string{`{"expected_head":null,"invitation_id":null}`, `{"expected_head":"head","invitation_id":"invite"}`} {
		var request IDTreeRegistrationRequest
		if err := json.Unmarshal([]byte(raw), &request); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(request)
		if err != nil || string(encoded) != raw {
			t.Fatalf("changed registration arguments: %s %v", encoded, err)
		}
	}
	for _, raw := range []string{`{}`, `{"expected_head":null}`, `{"invitation_id":null}`, `{"expected_head":1,"invitation_id":null}`} {
		var request IDTreeRegistrationRequest
		if err := json.Unmarshal([]byte(raw), &request); err == nil {
			t.Fatalf("accepted missing/malformed registration arguments: %s", raw)
		}
	}
}

func TestSpawnCreationSignsAndReadsIDTreeEnvelope(t *testing.T) {
	public, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	requestID := "20000000-0000-4000-8000-000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != spawnAcceptInvitePath {
			http.NotFound(w, request)
			return
		}
		raw, _ := io.ReadAll(request.Body)
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		var tree map[string]any
		if err := json.Unmarshal(body["id_tree"], &tree); err != nil {
			t.Error(err)
		}
		if tree["request_id"] != requestID {
			t.Errorf("wrong creation request: %s", raw)
		}
		auth := strings.Fields(request.Header.Get("Authorization"))
		if len(auth) != 3 || auth[0] != "DIDKey" || auth[1] != ComputeDIDKey(public) {
			t.Errorf("wrong subject proof: %v", auth)
			return
		}
		signature, err := base64.RawStdEncoding.DecodeString(auth[2])
		if err != nil {
			t.Error(err)
		}
		payload := onboardingDIDKeySignPayload(request.Method, request.URL.Path, request.Header.Get("X-AWEB-Timestamp"), raw)
		if !ed25519.Verify(public, payload, signature) {
			t.Error("creation object is outside the signed body")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id_chain":{"v":1,"type":"aweb.id-chain","certificates":[]},"registration_request":{"expected_head":null,"invitation_id":null}}`)
	}))
	defer server.Close()
	client, err := NewWithIdentity(server.URL, key, ComputeDIDKey(public))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.AcceptSpawnInvite(context.Background(), &SpawnAcceptInviteRequest{
		Token: "aw_inv_fixture", DID: ComputeDIDKey(public),
		IDTree: &IDTreeCreationRequest{V: 1, RequestID: requestID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.RegistrationRequest == nil || response.RegistrationRequest.ExpectedHead != nil || response.RegistrationRequest.InvitationID != nil {
		t.Fatalf("lost initial registration request: %+v", response)
	}
	if version, ok := response.IDChain["v"].(json.Number); !ok || version.String() != "1" {
		t.Fatalf("lost integer token: %+v", response.IDChain)
	}
}

func TestCreationResponseDistinguishesLegacyOmissionFromExplicitNull(t *testing.T) {
	for _, tt := range []struct {
		raw     string
		present bool
	}{
		{`{"team_id":"selected-team"}`, false},
		{`{"team_id":"selected-team","id_chain":null}`, true},
		{`{"team_id":"selected-team","registration_request":null}`, true},
		{`{"team_id":"selected-team","id_chain":null,"registration_request":null}`, true},
	} {
		var response SpawnAcceptInviteResponse
		if err := json.Unmarshal([]byte(tt.raw), &response); err != nil {
			t.Fatal(err)
		}
		if response.FieldsPresent != tt.present || response.TeamID != "selected-team" {
			t.Fatalf("lost constructor fields or presence: %+v", response)
		}
	}
}
