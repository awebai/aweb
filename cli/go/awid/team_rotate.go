package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Team-key rotation on the atomic path (docs/principal-attestation.md §5): the
// rotate request carries every team-key-signed record of the team, re-signed by
// the new key, and AWID swaps the key and the records in one transaction.

// SignedAttestationRecord is a stored record exactly as signed. Record numbers
// are json.Number, so the version keeps its literal form.
type SignedAttestationRecord struct {
	Record    map[string]any `json:"record"`
	Signature string         `json:"signature"`
}

// ResignedRecords is the rotate request's resigned_records object.
type ResignedRecords struct {
	TeamServer           *SignedAttestationRecord
	TeamCredentialPolicy *SignedAttestationRecord
	TeamCustodians       []SignedAttestationRecord
	MemberCustody        []SignedAttestationRecord
	MemberPerson         []SignedAttestationRecord
}

func (r *ResignedRecords) wire() map[string]any {
	list := func(records []SignedAttestationRecord) []SignedAttestationRecord {
		if records == nil {
			return []SignedAttestationRecord{}
		}
		return records
	}
	out := map[string]any{
		"team_custodians": list(r.TeamCustodians),
		"member_custody":  list(r.MemberCustody),
		"member_person":   list(r.MemberPerson),
	}
	if r.TeamServer != nil {
		out["team_server"] = r.TeamServer
	}
	if r.TeamCredentialPolicy != nil {
		out["team_credential_policy"] = r.TeamCredentialPolicy
	}
	return out
}

// ResignedRecordKeys names records per kind, as AWID's 409 does.
type ResignedRecordKeys struct {
	TeamServer           bool     `json:"team_server"`
	TeamCredentialPolicy bool     `json:"team_credential_policy"`
	TeamCustodians       []string `json:"team_custodians"`
	MemberCustody        []string `json:"member_custody"`
	MemberPerson         []string `json:"member_person"`
}

// IsEmpty reports whether no record is named.
func (k ResignedRecordKeys) IsEmpty() bool {
	return !k.TeamServer && !k.TeamCredentialPolicy && len(k.TeamCustodians) == 0 && len(k.MemberCustody) == 0 && len(k.MemberPerson) == 0
}

// ResignedRecordsIncomplete is AWID's 409 resigned_records_incomplete detail.
type ResignedRecordsIncomplete struct {
	Missing ResignedRecordKeys `json:"missing"`
	Extra   ResignedRecordKeys `json:"extra"`
	Changed ResignedRecordKeys `json:"changed"`
}

// ResignedRecordsIncompleteDetail returns the detail of a 409
// resigned_records_incomplete refusal, or false for any other error.
func ResignedRecordsIncompleteDetail(err error) (*ResignedRecordsIncomplete, bool) {
	var regErr *RegistryError
	if !errors.As(err, &regErr) || regErr.StatusCode != http.StatusConflict || !regErr.HasCode("resigned_records_incomplete") {
		return nil, false
	}
	var body struct {
		Detail ResignedRecordsIncomplete `json:"detail"`
	}
	if json.Unmarshal([]byte(regErr.Detail), &body) != nil {
		return nil, false
	}
	return &body.Detail, true
}

// TeamRotateResponse is AWID's answer to a team-key rotation.
type TeamRotateResponse struct {
	RegistryTeam
	KeyChanged bool `json:"key_changed"`
}

// RotateTeamKey replaces the team key at AWID, under namespace-controller
// authority. With resigned non-nil the records swap atomically with the key.
func (c *RegistryClient) RotateTeamKey(
	ctx context.Context,
	registryURL, domain, name, newTeamDIDKey string,
	resigned *ResignedRecords,
	controllerKey ed25519.PrivateKey,
) (*TeamRotateResponse, error) {
	domain = canonicalizeDomain(domain)
	name = strings.ToLower(strings.TrimSpace(name))
	if controllerKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}
	body := map[string]any{"new_team_did_key": newTeamDIDKey}
	if resigned != nil {
		body["resigned_records"] = resigned.wire()
	}
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/rotate"
	claims := map[string]string{"operation": "rotate_team_key", "domain": domain,
		"name":             name,
		"new_team_did_key": newTeamDIDKey,
	}
	var out TeamRotateResponse
	if err := c.ControllerRequest(ctx, http.MethodPost, registryURL, path, claims, controllerKey, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type attestationRecordWire struct {
	Record    json.RawMessage `json:"record"`
	Signature string          `json:"signature"`
}

func (c *RegistryClient) getAttestationRecord(ctx context.Context, registryURL, domain, name, suffix string) (*SignedAttestationRecord, error) {
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/teams/" +
		urlPathEscape(strings.ToLower(strings.TrimSpace(name))) + suffix
	var wire attestationRecordWire
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &wire); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire.Record))
	decoder.UseNumber()
	var record map[string]any
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode attestation record: %w", err)
	}
	return &SignedAttestationRecord{Record: record, Signature: wire.Signature}, nil
}

// GetTeamCustodianRecord reads a team's aweb.team-custodian/1 record anonymously.
func (c *RegistryClient) GetTeamCustodianRecord(ctx context.Context, registryURL, domain, name, custodianID string) (*SignedAttestationRecord, error) {
	return c.getAttestationRecord(ctx, registryURL, domain, name, "/custodians/"+urlPathEscape(custodianID))
}

// GetMemberCustodyRecord reads a certificate's aweb.member-custody/1 record anonymously.
func (c *RegistryClient) GetMemberCustodyRecord(ctx context.Context, registryURL, domain, name, certificateID string) (*SignedAttestationRecord, error) {
	return c.getAttestationRecord(ctx, registryURL, domain, name, "/certificates/"+urlPathEscape(certificateID)+"/custody")
}

// GetMemberPersonRecord reads a certificate's aweb.member-person/1 record anonymously.
func (c *RegistryClient) GetMemberPersonRecord(ctx context.Context, registryURL, domain, name, certificateID string) (*SignedAttestationRecord, error) {
	return c.getAttestationRecord(ctx, registryURL, domain, name, "/certificates/"+urlPathEscape(certificateID)+"/person")
}

// resignedIssuedAt is now, or one second after the stored issued_at when the
// local clock is not ahead of it: AWID accepts only newer records.
func resignedIssuedAt(stored any, now time.Time) (time.Time, error) {
	text, _ := stored.(string)
	storedAt, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		return time.Time{}, fmt.Errorf("stored issued_at %q is not a valid time", text)
	}
	now = now.UTC().Truncate(time.Second)
	if !now.After(storedAt) {
		return storedAt.Add(time.Second), nil
	}
	return now, nil
}

// ResignAttestationRecord returns the record with team_did_key set to the new
// key and a newer issued_at, signed by the new key. Every other field is kept.
func ResignAttestationRecord(newTeamKey ed25519.PrivateKey, record map[string]any, now time.Time) (SignedAttestationRecord, error) {
	issuedAt, err := resignedIssuedAt(record["issued_at"], now)
	if err != nil {
		return SignedAttestationRecord{}, err
	}
	resigned := make(map[string]any, len(record))
	for key, value := range record {
		resigned[key] = value
	}
	resigned["team_did_key"] = ComputeDIDKey(newTeamKey.Public().(ed25519.PublicKey))
	resigned["issued_at"] = issuedAt.Format("2006-01-02T15:04:05Z")
	signature, err := SignAttestationRecord(newTeamKey, resigned)
	if err != nil {
		return SignedAttestationRecord{}, err
	}
	return SignedAttestationRecord{Record: resigned, Signature: signature}, nil
}

// ResignTeamServerRecord returns the team's aweb.team-server/1 record for the
// new key: the same server_url, a newer issued_at, signed by the new key.
func ResignTeamServerRecord(newTeamKey ed25519.PrivateKey, record map[string]any, now time.Time) (SignedAttestationRecord, error) {
	issuedAt, err := resignedIssuedAt(record["issued_at"], now)
	if err != nil {
		return SignedAttestationRecord{}, err
	}
	teamID, _ := record["team_id"].(string)
	serverURL, _ := record["server_url"].(string)
	resigned := NewTeamServerRecord(teamID, ComputeDIDKey(newTeamKey.Public().(ed25519.PublicKey)), serverURL, issuedAt)
	signature, err := SignTeamServerRecord(newTeamKey, resigned)
	if err != nil {
		return SignedAttestationRecord{}, err
	}
	return SignedAttestationRecord{Record: resigned, Signature: signature}, nil
}

// signedRecordsPageCap bounds the signed-records walk, as certificateListPageCap
// does certificate listing, so a registry that keeps reporting more pages cannot
// keep aw reading forever. At AWID's largest page it is 100,000 records.
const signedRecordsPageCap = 500

// SignedRecordItem is one record of a team's paginated signed-records read.
// Key is nil for team-server and credential-policy records.
type SignedRecordItem struct {
	Kind string
	Key  *string
	SignedAttestationRecord
}

// ListTeamSignedRecords reads every team-key-signed record the team has stored,
// page by page, signed with the team controller key. AWID answers any refusal
// as an unknown team.
func (c *RegistryClient) ListTeamSignedRecords(
	ctx context.Context,
	registryURL, domain, name string,
	pageSize int,
	signingKey ed25519.PrivateKey,
) ([]SignedRecordItem, error) {
	if signingKey == nil {
		return nil, fmt.Errorf("team signing key is required")
	}
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/teams/" +
		urlPathEscape(strings.ToLower(strings.TrimSpace(name))) + "/signed-records"
	var items []SignedRecordItem
	cursor := ""
	for page := 0; page < signedRecordsPageCap; page++ {
		query := url.Values{}
		if pageSize > 0 {
			query.Set("limit", strconv.Itoa(pageSize))
		}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		target := path
		if encoded := query.Encode(); encoded != "" {
			target += "?" + encoded
		}
		var pageBody struct {
			Items []struct {
				Kind      string          `json:"kind"`
				Key       *string         `json:"key"`
				Record    json.RawMessage `json:"record"`
				Signature string          `json:"signature"`
			} `json:"items"`
			HasMore    bool    `json:"has_more"`
			NextCursor *string `json:"next_cursor"`
		}
		headers := optionalSignedPathHeaders(http.MethodGet, path, signingKey)
		if err := c.requestJSON(ctx, http.MethodGet, registryURL, target, headers, nil, &pageBody); err != nil {
			return nil, err
		}
		for _, item := range pageBody.Items {
			decoder := json.NewDecoder(bytes.NewReader(item.Record))
			decoder.UseNumber()
			var record map[string]any
			if err := decoder.Decode(&record); err != nil {
				return nil, fmt.Errorf("decode signed record: %w", err)
			}
			items = append(items, SignedRecordItem{
				Kind: item.Kind, Key: item.Key,
				SignedAttestationRecord: SignedAttestationRecord{Record: record, Signature: item.Signature},
			})
		}
		if !pageBody.HasMore {
			return items, nil
		}
		if pageBody.NextCursor == nil || *pageBody.NextCursor == "" || *pageBody.NextCursor == cursor {
			return nil, fmt.Errorf("signed-records read: AWID reported more records without a new cursor")
		}
		cursor = *pageBody.NextCursor
	}
	return nil, fmt.Errorf("signed-records read of %s:%s is truncated at %d records: AWID still reports more after %d pages",
		name, domain, len(items), signedRecordsPageCap)
}
