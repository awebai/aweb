package awid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type signedCertificatePresenceFixture struct {
	Certificate map[string]any `json:"certificate"`
	Header      string         `json:"header"`
	TeamKey     string         `json:"expected_team_did_key"`
	MemberKey   string         `json:"expected_member_did_key"`
}

func readSignedEmptyOptionalCertificate(t *testing.T) signedCertificatePresenceFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "team-certificate-empty-optionals.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture signedCertificatePresenceFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestDecodedCertificatePreservesSignedEmptyOptionalFields(t *testing.T) {
	checkCertificatePresenceRoundTrip(t, readSignedEmptyOptionalCertificate(t))
}

func checkCertificatePresenceRoundTrip(t *testing.T, fixture signedCertificatePresenceFixture) {
	t.Helper()
	if _, err := CheckTeamCertificate(fixture.Header, TeamCertificateFacts{
		SubjectDIDKey: fixture.MemberKey,
		TeamDIDKey:    fixture.TeamKey,
		Registered:    RegistrationNotRequired(),
	}); err != nil {
		t.Fatalf("raw signed certificate refused: %v", err)
	}
	certificate, err := DecodeTeamCertificateHeader(fixture.Header)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDecodedTeamCertificate(certificate, fixture.TeamKey); err != nil {
		t.Fatalf("decoded signed certificate refused: %v", err)
	}
	path := filepath.Join(t.TempDir(), "certificate.json")
	if err := SaveTeamCertificate(path, certificate); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadTeamCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDecodedTeamCertificate(stored, fixture.TeamKey); err != nil {
		t.Fatalf("stored signed certificate refused: %v", err)
	}
	header, err := EncodeTeamCertificateHeader(stored)
	if err != nil {
		t.Fatal(err)
	}
	data, err := DecodeTeamCertificate(header)
	if err != nil {
		t.Fatal(err)
	}
	// The JSON meaning, including signed field presence, must survive storage.
	if !reflect.DeepEqual(data, fixture.Certificate) {
		t.Fatalf("round trip changed signed fields: got %v, want %v", data, fixture.Certificate)
	}
}

func TestDecodedCertificateRejectsMutationOfSignedEmptyOptionalFields(t *testing.T) {
	fixture := readSignedEmptyOptionalCertificate(t)
	for _, field := range []string{"member_did_aw", "member_address", "alias"} {
		t.Run(field, func(t *testing.T) {
			certificate, err := DecodeTeamCertificateHeader(fixture.Header)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckDecodedTeamCertificate(certificate, fixture.TeamKey); err != nil {
				t.Fatalf("unchanged control refused: %v", err)
			}
			switch field {
			case "member_did_aw":
				certificate.MemberDIDAW = "did:aw:changed"
			case "member_address":
				certificate.MemberAddress = "acme.com/changed"
			case "alias":
				certificate.Alias = "changed"
			}
			var refusal *TeamCertificateError
			if err := CheckDecodedTeamCertificate(certificate, fixture.TeamKey); !errors.As(err, &refusal) || refusal.Reason != "bad_signature" {
				t.Fatalf("mutation err=%v, want bad_signature", err)
			}
		})
	}
}

func TestCertificateMemberFieldPresenceSurvivesBothScopeForms(t *testing.T) {
	fixture := readSignedEmptyOptionalCertificate(t)
	teamPublic, teamPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	scopes := []struct {
		field string
		value string
	}{
		{field: "identity_scope", value: IdentityModeLocal},
		{field: "lifetime", value: "persistent"},
	}
	members := []struct {
		name   string
		fields map[string]any
	}{
		{name: "absent", fields: map[string]any{}},
		{name: "empty_did", fields: map[string]any{"member_did_aw": ""}},
		{name: "empty_address", fields: map[string]any{"member_address": ""}},
		{name: "both_empty", fields: map[string]any{"member_did_aw": "", "member_address": ""}},
		{name: "null", fields: map[string]any{"member_did_aw": nil, "member_address": nil}},
		{name: "nonempty", fields: map[string]any{"member_did_aw": "did:aw:member", "member_address": "acme.com/alice"}},
	}
	for _, scope := range scopes {
		for _, member := range members {
			t.Run(scope.field+"/"+member.name, func(t *testing.T) {
				claims := make(map[string]any, len(fixture.Certificate))
				for name, value := range fixture.Certificate {
					if name != "signature" && name != "member_did_aw" && name != "member_address" && name != "identity_scope" {
						claims[name] = value
					}
				}
				claims["team_did_key"] = ComputeDIDKey(teamPublic)
				claims[scope.field] = scope.value
				for name, value := range member.fields {
					claims[name] = value
				}
				payload, err := CanonicalJSONValue(claims)
				if err != nil {
					t.Fatal(err)
				}
				claims["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamPrivate, []byte(payload)))
				data, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				checkCertificatePresenceRoundTrip(t, signedCertificatePresenceFixture{
					Certificate: claims,
					Header:      base64.StdEncoding.EncodeToString(data),
					TeamKey:     ComputeDIDKey(teamPublic),
					MemberKey:   fixture.MemberKey,
				})
			})
		}
	}
}
