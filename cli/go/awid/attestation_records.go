package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The team-key-signed AWID records behind principal attestation
// (docs/principal-attestation.md, docs/member-person.md). Each record is signed
// with the team key over "<type>/1\n" followed by its canonical JSON; the
// signature is unpadded base64url with exactly one accepted encoding.
const (
	TeamCustodianRecordType = "aweb.team-custodian"
	MemberCustodyRecordType = "aweb.member-custody"
	MemberPersonRecordType  = "aweb.member-person"
)

var (
	attestationRecordCommonFields = []string{"v", "type", "team_id", "team_did_key", "issued_at"}
	attestationRecordFields       = map[string][]string{
		TeamCustodianRecordType: {"custodian_id", "issuer_did_keys"},
		MemberCustodyRecordType: {"certificate_id", "member_did_key", "custodian_id"},
		MemberPersonRecordType:  {"certificate_id", "member_did_key", "single_person"},
	}
	attestationTimestampRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	attestationCustodianIDRE = regexp.MustCompile(`^[a-z0-9.-]{1,128}$`)
	attestationCertificateRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
)

// AttestationRecordError is a refused record. Its Code is record_invalid.
type AttestationRecordError struct {
	Code    string
	Message string
}

func (e *AttestationRecordError) Error() string {
	return e.Code + ": " + e.Message
}

// AttestationRecordErrorCode returns the refusal code of err, or "".
func AttestationRecordErrorCode(err error) string {
	var recordErr *AttestationRecordError
	if errors.As(err, &recordErr) {
		return recordErr.Code
	}
	return ""
}

func attestationRecordRefusal(message string) error {
	return &AttestationRecordError{Code: "record_invalid", Message: message}
}

// AttestationRecordSigningBytes is "<type>/1\n" followed by the record's
// canonical JSON, for any of the three record types.
func AttestationRecordSigningBytes(record map[string]any) ([]byte, error) {
	recordType, _ := record["type"].(string)
	if _, ok := attestationRecordFields[recordType]; !ok {
		return nil, attestationRecordRefusal("unknown record type")
	}
	canonical, err := CanonicalJSONValue(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(recordType+"/1\n"), canonical...), nil
}

// SignAttestationRecord signs a record with the team key, returning unpadded
// base64url.
func SignAttestationRecord(teamKey ed25519.PrivateKey, record map[string]any) (string, error) {
	signingBytes, err := AttestationRecordSigningBytes(record)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(teamKey, signingBytes)), nil
}

func attestationVersionIsOne(value any) bool {
	switch v := value.(type) {
	case int:
		return v == 1
	case json.Number:
		return v.String() == "1"
	default:
		return false
	}
}

func requireAttestationDIDKey(value any, field string) error {
	did, ok := value.(string)
	if !ok || !strings.HasPrefix(did, "did:key:z") {
		return attestationRecordRefusal(field + " must be a did:key")
	}
	if _, err := ExtractPublicKey(did); err != nil {
		return attestationRecordRefusal(field + " is not a valid did:key")
	}
	return nil
}

// ValidateAttestationRecord checks a record's shape for its declared type.
func ValidateAttestationRecord(record map[string]any) error {
	recordType, _ := record["type"].(string)
	specific, ok := attestationRecordFields[recordType]
	if !ok {
		return attestationRecordRefusal("unknown record type")
	}
	fields := append(append([]string{}, attestationRecordCommonFields...), specific...)
	if len(record) != len(fields) {
		return attestationRecordRefusal("record must have exactly the " + recordType + "/1 fields")
	}
	for _, field := range fields {
		if _, ok := record[field]; !ok {
			return attestationRecordRefusal("record must have exactly the " + recordType + "/1 fields")
		}
	}
	if !attestationVersionIsOne(record["v"]) {
		return attestationRecordRefusal("record must be version 1")
	}
	teamID, ok := record["team_id"].(string)
	if !ok {
		return attestationRecordRefusal("team_id must be a string")
	}
	if _, _, err := ParseTeamID(teamID); err != nil {
		return attestationRecordRefusal("invalid team_id")
	}
	if err := requireAttestationDIDKey(record["team_did_key"], "team_did_key"); err != nil {
		return err
	}
	issuedAt, ok := record["issued_at"].(string)
	if !ok || !attestationTimestampRE.MatchString(issuedAt) {
		return attestationRecordRefusal("issued_at must be RFC 3339 UTC seconds (YYYY-MM-DDTHH:MM:SSZ)")
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", issuedAt); err != nil {
		return attestationRecordRefusal("issued_at is not a valid time")
	}
	if _, ok := record["certificate_id"]; ok {
		certificateID, ok := record["certificate_id"].(string)
		if !ok || !attestationCertificateRE.MatchString(certificateID) {
			return attestationRecordRefusal("invalid certificate_id")
		}
		if err := requireAttestationDIDKey(record["member_did_key"], "member_did_key"); err != nil {
			return err
		}
	}
	if _, ok := record["custodian_id"]; ok {
		custodianID, ok := record["custodian_id"].(string)
		if !ok || !attestationCustodianIDRE.MatchString(custodianID) {
			return attestationRecordRefusal("invalid custodian_id")
		}
	}
	switch recordType {
	case TeamCustodianRecordType:
		keys, ok := record["issuer_did_keys"].([]any)
		if !ok || len(keys) > 2 {
			return attestationRecordRefusal("issuer_did_keys must hold zero to two distinct keys")
		}
		seen := map[string]bool{}
		for _, key := range keys {
			if err := requireAttestationDIDKey(key, "issuer_did_keys"); err != nil {
				return err
			}
			if seen[key.(string)] {
				return attestationRecordRefusal("issuer_did_keys must hold zero to two distinct keys")
			}
			seen[key.(string)] = true
		}
	case MemberPersonRecordType:
		if _, ok := record["single_person"].(bool); !ok {
			return attestationRecordRefusal("single_person must be a boolean")
		}
	}
	return nil
}

// decodeAttestationSignature accepts only the one unpadded base64url encoding
// of a 64-byte Ed25519 signature.
func decodeAttestationSignature(signature string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != signature || len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be one unpadded base64url Ed25519 signature")
	}
	return raw, nil
}

// VerifyAttestationRecord validates a record, requires it to name teamDIDKey
// and verifies its signature under that key.
func VerifyAttestationRecord(record map[string]any, signature, teamDIDKey string) error {
	if err := ValidateAttestationRecord(record); err != nil {
		return err
	}
	if record["team_did_key"] != teamDIDKey {
		return attestationRecordRefusal("record is not signed for this team key")
	}
	raw, err := decodeAttestationSignature(signature)
	if err != nil {
		return attestationRecordRefusal(err.Error())
	}
	publicKey, err := ExtractPublicKey(teamDIDKey)
	if err != nil {
		return attestationRecordRefusal("team key is not a did:key")
	}
	signingBytes, err := AttestationRecordSigningBytes(record)
	if err != nil {
		return attestationRecordRefusal("record cannot be canonicalized")
	}
	if !ed25519.Verify(publicKey, signingBytes, raw) {
		return attestationRecordRefusal("signature does not verify against the team key")
	}
	return nil
}
