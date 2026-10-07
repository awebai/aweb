package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/awebai/aw/awconfig"
)

// Inspect errors deliberately retain no decoder, transport or service error:
// those errors can contain the capability supplied on stdin.
type inviteInspectError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	exit    int
}

func (e *inviteInspectError) Error() string { return e.Code + ": " + e.Message }
func (e *inviteInspectError) ExitCode() int { return e.exit }

func malformedInspectToken() *inviteInspectError {
	return &inviteInspectError{"malformed_token", "Invite token is malformed or incomplete.", 1}
}

func unsupportedInspectToken() *inviteInspectError {
	return &inviteInspectError{"unsupported_version", "Invite token version is not supported by this CLI.", 1}
}

// Unlike acceptance's stdin reader, inspection must distinguish an unsupported
// envelope version from malformed input. Keep acceptance behavior unchanged.
func readInspectToken(reader io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, inviteTokenStdinLimit+1))
	if err != nil {
		return "", &inviteInspectError{"malformed_token", "Cannot read invite token from stdin.", 2}
	}
	if len(data) > inviteTokenStdinLimit {
		return "", &inviteInspectError{"malformed_token", "Invite token stdin exceeds 65536 bytes.", 2}
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", &inviteInspectError{"malformed_token", "Supply one invite token line on stdin, then close the pipe.", 2}
	}
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", malformedInspectToken()
		}
	}
	return token, nil
}

var inspectVersionPrefix = regexp.MustCompile(`^aw_inv_v[0-9]+_`)
var inspectInnerToken = regexp.MustCompile(`^aw_inv_[A-Za-z0-9_-]+$`)

func decodeInspectHostedEnvelope(token string) (hostedJoinTokenEnvelope, error) {
	var envelope hostedJoinTokenEnvelope
	// A legacy random token can start with v1_. It contains no server URL,
	// and inspect must not discover a destination from principal state.
	if legacyHostedJoinTokenPattern.MatchString(token) {
		return envelope, &inviteInspectError{"malformed_token", "A hosted invite envelope with a server URL is required; request a new shareable invite.", 1}
	}
	if !strings.HasPrefix(token, hostedJoinTokenPrefix) {
		if inspectVersionPrefix.MatchString(token) {
			return envelope, unsupportedInspectToken()
		}
		return envelope, malformedInspectToken()
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, hostedJoinTokenPrefix))
	if err != nil || json.Unmarshal(data, &envelope) != nil {
		return hostedJoinTokenEnvelope{}, malformedInspectToken()
	}
	if envelope.Version != 1 {
		return hostedJoinTokenEnvelope{}, unsupportedInspectToken()
	}
	if len(envelope.InnerToken) > 256 || !inspectInnerToken.MatchString(envelope.InnerToken) {
		return hostedJoinTokenEnvelope{}, malformedInspectToken()
	}
	envelope.AwebURL, err = inspectServiceURL(envelope.AwebURL)
	if err != nil {
		return hostedJoinTokenEnvelope{}, err
	}
	if strings.Contains(envelope.AwebURL, envelope.InnerToken) || strings.Contains(envelope.AwebURL, strings.TrimPrefix(envelope.InnerToken, "aw_inv_")) {
		return hostedJoinTokenEnvelope{}, malformedInspectToken()
	}
	return envelope, nil
}

// Reject URL credentials instead of silently sending them. No caller may expose
// the original URL or an underlying parser error in output or trace.
func inspectServiceURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", malformedInspectToken()
	}
	normalized, err := validateInviteAwebURL(raw)
	if err != nil {
		return "", malformedInspectToken()
	}
	return normalized, nil
}

func decodeInspectControllerToken(token string) (*awconfig.TeamInviteToken, error) {
	decoded, err := awconfig.DecodeInviteToken(token)
	if err != nil {
		return nil, malformedInspectToken()
	}
	if decoded.AwebURL != "" {
		decoded.AwebURL, err = inspectServiceURL(decoded.AwebURL)
		if err != nil {
			return nil, err
		}
	}
	return decoded, nil
}
