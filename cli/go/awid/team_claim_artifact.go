package awid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const maxTeamClaimArtifactBytes = 16384

// SignedUnownedTeamClaim is the shared carrier in docs/unowned-team-claim.md.
// The embedded signer supplies the integrity key. The host checks freshness
// and current controller authority.
type SignedUnownedTeamClaim struct {
	Request      UnownedTeamClaimRequest
	SignerDIDKey string
	Signature    string
}

func (claim SignedUnownedTeamClaim) VerifyIntegrity() error {
	return claim.Request.verifySignature(teamClaimSignature{signerDIDKey: claim.SignerDIDKey, signature: claim.Signature})
}

// MarshalJSON serializes the single artifact schema, including its fixed purpose.
func (claim SignedUnownedTeamClaim) MarshalJSON() ([]byte, error) {
	if _, err := claim.Request.SigningBytes(); err != nil {
		return nil, err
	}
	return teamControlPayload(map[string]any{"request": claim.Request.payload(), "signer_did_key": claim.SignerDIDKey, "signature": claim.Signature})
}

// ParseUnownedTeamClaim refuses duplicate/extra fields, invalid Unicode, and
// trailing data. Parsing never issues an authenticated controller result.
func ParseUnownedTeamClaim(raw []byte) (SignedUnownedTeamClaim, error) {
	var claim SignedUnownedTeamClaim
	if len(raw) > maxTeamClaimArtifactBytes || !validClaimJSONUnicode(raw) {
		return claim, fmt.Errorf("invalid claim JSON size or Unicode; regenerate the artifact and retry")
	}
	fields, err := claimJSONObject(raw)
	if err != nil {
		return claim, err
	}
	if !claimFieldsMatch(fields, []string{"request", "signer_did_key", "signature"}) {
		return claim, fmt.Errorf("unexpected claim fields; regenerate the artifact and retry")
	}
	request, err := claimJSONObject(fields["request"])
	if err != nil {
		return claim, err
	}
	if !claimFieldsMatch(request, []string{"operation", "awid_team_id", "email", "username", "timestamp"}) {
		return claim, fmt.Errorf("unexpected claim request fields; regenerate the artifact and retry")
	}
	var operation string
	targets := map[string]*string{"operation": &operation, "awid_team_id": &claim.Request.AWIDTeamID, "email": &claim.Request.Email, "username": &claim.Request.Username, "timestamp": &claim.Request.Timestamp}
	for name, target := range targets {
		if err := claimJSONString(request[name], target); err != nil {
			return claim, err
		}
	}
	if operation != unownedTeamClaimOperation {
		return claim, fmt.Errorf("wrong claim operation; regenerate the artifact and retry")
	}
	if err := claimJSONString(fields["signer_did_key"], &claim.SignerDIDKey); err != nil {
		return claim, err
	}
	if err := claimJSONString(fields["signature"], &claim.Signature); err != nil {
		return claim, err
	}
	if _, err := claim.Request.SigningBytes(); err != nil {
		return claim, err
	}
	return claim, nil
}
func claimJSONString(raw []byte, target *string) error {
	if len(raw) == 0 || raw[0] != '"' {
		return fmt.Errorf("claim fields must be strings; regenerate the artifact and retry")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("invalid claim string: %w; regenerate the artifact and retry", err)
	}
	return nil
}
func claimFieldsMatch(fields map[string]json.RawMessage, names []string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}
func claimJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, fmt.Errorf("claim JSON must be an object; regenerate the artifact and retry")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid claim field: %w; regenerate the artifact and retry", err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid claim field name; regenerate the artifact and retry")
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("duplicate claim field; regenerate the artifact and retry")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid claim value: %w; regenerate the artifact and retry", err)
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("invalid claim object: %w; regenerate the artifact and retry", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing claim JSON; regenerate the artifact and retry")
	}
	return fields, nil
}

// encoding/json replaces lone surrogates with U+FFFD. Reject that lossy input
// instead: the Python reader and both signers bind Unicode scalar values.
func validClaimJSONUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		point := rune(value)
		if !utf16.IsSurrogate(point) {
			continue
		}
		if point < 0xd800 || point > 0xdbff || i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
