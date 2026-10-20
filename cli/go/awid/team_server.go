package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// aweb.team-server/1: a team-key-signed binding of a team to its coordination
// server. The team controller signs, with the team key, the domain prefix
// followed by the canonical JSON of the record. Consumers verify it against the
// team's current key from the registry they already trust for that team.
const (
	TeamServerSigningPrefix    = "aweb.team-server/1\n"
	TeamServerRecordType       = "aweb.team-server"
	TeamServerRecordVersion    = 1
	TeamServerMaxFutureSeconds = 300
	TeamServerMaxURLBytes      = 2048
)

var (
	teamServerRecordFields = []string{"v", "type", "team_id", "team_did_key", "server_url", "issued_at"}
	teamServerIssuedAtRE   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
)

// TeamServerRecordError is a refused record. Code is stable and distinct per
// refusal: record_invalid, team_mismatch, team_server_key_mismatch and
// signature_invalid for a record that does not verify; server_url_invalid and
// issued_at_in_future for a verified record that is still refused.
type TeamServerRecordError struct {
	Code    string
	Message string
}

func (e *TeamServerRecordError) Error() string {
	return e.Code + ": " + e.Message
}

// TeamServerRecordErrorCode returns the refusal code of err, or "".
func TeamServerRecordErrorCode(err error) string {
	var recordErr *TeamServerRecordError
	if errors.As(err, &recordErr) {
		return recordErr.Code
	}
	return ""
}

func teamServerRefusal(code, message string) error {
	return &TeamServerRecordError{Code: code, Message: message}
}

// VerifiedTeamServerRecord is a record that verified for its team.
type VerifiedTeamServerRecord struct {
	TeamID     string
	TeamDIDKey string
	ServerURL  string
	Audience   string
	IssuedAt   time.Time
}

// NewTeamServerRecord builds the record the team key signs.
func NewTeamServerRecord(teamID, teamDIDKey, serverURL string, issuedAt time.Time) map[string]any {
	return map[string]any{
		"v":            TeamServerRecordVersion,
		"type":         TeamServerRecordType,
		"team_id":      teamID,
		"team_did_key": teamDIDKey,
		"server_url":   serverURL,
		"issued_at":    issuedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// TeamServerRecordSigningBytes is the domain prefix followed by the record's
// canonical JSON.
func TeamServerRecordSigningBytes(record map[string]any) ([]byte, error) {
	canonical, err := CanonicalJSONValue(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(TeamServerSigningPrefix), canonical...), nil
}

// SignTeamServerRecord signs a record with the team key, returning unpadded
// standard base64.
func SignTeamServerRecord(teamKey ed25519.PrivateKey, record map[string]any) (string, error) {
	signingBytes, err := TeamServerRecordSigningBytes(record)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, signingBytes)), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CanonicalTeamServerURL returns (server_url, audience) for a canonical team
// server URL: an https origin with an optional path prefix, lower-case scheme
// and host, no default port, no trailing slash or empty segment, no userinfo,
// params, query or fragment, at most TeamServerMaxURLBytes bytes. Plain http
// and literal IP addresses are accepted only for loopback hosts.
func CanonicalTeamServerURL(value string) (string, string, error) {
	refuse := func(reason string) (string, string, error) {
		return "", "", teamServerRefusal("server_url_invalid", "server_url "+reason)
	}
	if value == "" {
		return refuse("is required")
	}
	if len(value) > TeamServerMaxURLBytes {
		return refuse(fmt.Sprintf("must be at most %d bytes", TeamServerMaxURLBytes))
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return refuse("is not a URL")
	}
	scheme := parsed.Scheme
	if scheme != "http" && scheme != "https" {
		return refuse("must use https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.ContainsAny(value, "?#") {
		return refuse("must not include userinfo, params, query or fragment")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return refuse("must include a host")
	}
	port := parsed.Port()
	defaultPort := "443"
	if scheme == "http" {
		defaultPort = "80"
	}
	hostOut := host
	if strings.Contains(host, ":") {
		hostOut = "[" + host + "]"
	}
	audience := scheme + "://" + hostOut
	if port != "" && port != defaultPort {
		audience += ":" + port
	}
	if !strings.HasPrefix(value, audience) {
		return refuse("must be in canonical form")
	}
	path := value[len(audience):]
	if path != "" && !strings.HasPrefix(path, "/") {
		return refuse("must be in canonical form")
	}
	if strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return refuse("must not end with a slash or contain empty segments")
	}
	if segments := strings.Split(path, "/"); strings.Contains(segments[len(segments)-1], ";") {
		return refuse("must not include userinfo, params, query or fragment")
	}
	loopback := isLoopbackHost(host)
	if scheme == "http" && !loopback {
		return refuse("must use https outside loopback hosts")
	}
	if net.ParseIP(host) != nil && !loopback {
		return refuse("must not use a literal IP address")
	}
	return value, audience, nil
}

// teamServerVersionIsOne accepts the integer 1: an int in a record built in
// memory, or the JSON literal 1 in a record decoded with UseNumber. A float,
// a decimal literal such as 1.0 and a boolean are refused, as Python does.
func teamServerVersionIsOne(value any) bool {
	switch v := value.(type) {
	case int:
		return v == TeamServerRecordVersion
	case json.Number:
		return v.String() == "1"
	default:
		return false
	}
}

// decodeTeamServerSignature accepts only unpadded standard base64 of a 64-byte
// Ed25519 signature, as the Python verifier and the vector do.
func decodeTeamServerSignature(signature string) ([]byte, error) {
	if len(signature) != 86 {
		return nil, fmt.Errorf("signature must be 86 characters of unpadded standard base64")
	}
	return base64.RawStdEncoding.Strict().DecodeString(signature)
}

// VerifyTeamServerRecord verifies one record for teamID against the team's
// current key. Refusals are *TeamServerRecordError values.
func VerifyTeamServerRecord(record map[string]any, signature, teamID, currentTeamDIDKey string, now time.Time) (*VerifiedTeamServerRecord, error) {
	if len(record) != len(teamServerRecordFields) {
		return nil, teamServerRefusal("record_invalid", "record must have exactly the aweb.team-server/1 fields")
	}
	for _, field := range teamServerRecordFields {
		if _, ok := record[field]; !ok {
			return nil, teamServerRefusal("record_invalid", "record must have exactly the aweb.team-server/1 fields")
		}
	}
	if !teamServerVersionIsOne(record["v"]) || record["type"] != TeamServerRecordType {
		return nil, teamServerRefusal("record_invalid", "record must be version 1 of aweb.team-server")
	}
	strs := map[string]string{}
	for _, field := range []string{"team_id", "team_did_key", "server_url", "issued_at"} {
		value, ok := record[field].(string)
		if !ok {
			return nil, teamServerRefusal("record_invalid", "record fields must be strings")
		}
		strs[field] = value
	}
	if !teamServerIssuedAtRE.MatchString(strs["issued_at"]) {
		return nil, teamServerRefusal("record_invalid", "issued_at must be RFC 3339 UTC seconds (YYYY-MM-DDTHH:MM:SSZ)")
	}
	issuedAt, err := time.Parse("2006-01-02T15:04:05Z", strs["issued_at"])
	if err != nil {
		return nil, teamServerRefusal("record_invalid", "issued_at must be RFC 3339 UTC seconds (YYYY-MM-DDTHH:MM:SSZ)")
	}
	if strs["team_id"] != teamID {
		return nil, teamServerRefusal("team_mismatch", "record names another team")
	}
	if strs["team_did_key"] != currentTeamDIDKey {
		return nil, teamServerRefusal("team_server_key_mismatch", "record is not signed by the team's current key")
	}
	if signature == "" {
		return nil, teamServerRefusal("signature_invalid", "signature is required")
	}
	publicKey, err := ExtractPublicKey(currentTeamDIDKey)
	if err != nil {
		return nil, teamServerRefusal("team_server_key_mismatch", "team key is not a did:key")
	}
	signatureBytes, err := decodeTeamServerSignature(signature)
	if err != nil {
		return nil, teamServerRefusal("signature_invalid", "signature is not base64")
	}
	signingBytes, err := TeamServerRecordSigningBytes(record)
	if err != nil {
		return nil, teamServerRefusal("record_invalid", "record cannot be canonicalized")
	}
	if !ed25519.Verify(publicKey, signingBytes, signatureBytes) {
		return nil, teamServerRefusal("signature_invalid", "signature does not verify against the team key")
	}
	serverURL, audience, err := CanonicalTeamServerURL(strs["server_url"])
	if err != nil {
		return nil, err
	}
	if issuedAt.After(now.Add(TeamServerMaxFutureSeconds * time.Second)) {
		return nil, teamServerRefusal("issued_at_in_future", "issued_at is too far in the future")
	}
	return &VerifiedTeamServerRecord{
		TeamID:     teamID,
		TeamDIDKey: currentTeamDIDKey,
		ServerURL:  serverURL,
		Audience:   audience,
		IssuedAt:   issuedAt,
	}, nil
}

// TeamServerRecordResponse is AWID's stored record, exactly as signed. Record
// numbers are json.Number, so the version keeps its literal form.
type TeamServerRecordResponse struct {
	Record    map[string]any `json:"record"`
	Signature string         `json:"signature"`
}

type teamServerRecordWire struct {
	Record    json.RawMessage `json:"record"`
	Signature string          `json:"signature"`
}

func (w teamServerRecordWire) decode() (*TeamServerRecordResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(w.Record))
	decoder.UseNumber()
	var record map[string]any
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode team server record: %w", err)
	}
	return &TeamServerRecordResponse{Record: record, Signature: w.Signature}, nil
}

func teamServerPath(domain, name string) string {
	return "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/teams/" + urlPathEscape(strings.ToLower(strings.TrimSpace(name))) + "/server"
}

// PublishTeamServerRecord stores a signed record at the registry. The record's
// own team-key signature is the authority; no request signature is sent.
func (c *RegistryClient) PublishTeamServerRecord(ctx context.Context, registryURL, domain, name string, record map[string]any, signature string) (*TeamServerRecordResponse, error) {
	var out teamServerRecordWire
	body := map[string]any{"record": record, "signature": signature}
	if err := c.requestJSON(ctx, http.MethodPut, registryURL, teamServerPath(domain, name), nil, body, &out); err != nil {
		return nil, err
	}
	return out.decode()
}

// GetTeamServerRecord reads the team's stored record anonymously.
func (c *RegistryClient) GetTeamServerRecord(ctx context.Context, registryURL, domain, name string) (*TeamServerRecordResponse, error) {
	var out teamServerRecordWire
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, teamServerPath(domain, name), nil, nil, &out); err != nil {
		return nil, err
	}
	return out.decode()
}
