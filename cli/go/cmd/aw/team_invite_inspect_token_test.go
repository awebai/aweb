package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func inspectEnvelopeFixture(version int, inner, server string) string {
	b, _ := json.Marshal(hostedJoinTokenEnvelope{Version: version, InnerToken: inner, AwebURL: server})
	return hostedJoinTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func TestInspectTokenParsing(t *testing.T) {
	const secret = "aw_inv_fixture_secret"
	valid := inspectEnvelopeFixture(1, secret, "https://example.test/api")
	read, err := readInspectToken(strings.NewReader(" \n" + valid + "\n"))
	if err != nil || read != valid {
		t.Fatal("stdin did not retain the token")
	}
	envelope, err := decodeInspectHostedEnvelope(read)
	if err != nil || envelope.InnerToken != secret || envelope.AwebURL != "https://example.test/api" {
		t.Fatal("hosted envelope did not decode")
	}
	for _, tc := range []struct{ name, input, code string }{
		{"malformed", "aw_inv_v1_not-json", "malformed_token"},
		{"version", inspectEnvelopeFixture(2, secret, "https://example.test"), "unsupported_version"},
		{"prefix_version", "aw_inv_v2_future", "unsupported_version"},
		{"legacy_collision", "aw_inv_v1_" + strings.Repeat("A", 40), "malformed_token"},
		{"credentials", inspectEnvelopeFixture(1, secret, "https://user:"+secret+"@example.test"), "malformed_token"},
		{"query", inspectEnvelopeFixture(1, secret, "https://example.test/?token="+secret), "malformed_token"},
		{"secret_path", inspectEnvelopeFixture(1, secret, "https://example.test/"+secret), "malformed_token"},
		{"inner_limit", inspectEnvelopeFixture(1, "aw_inv_"+strings.Repeat("x", 250), "https://example.test"), "malformed_token"},
		{"bad_url", inspectEnvelopeFixture(1, secret, "file:///tmp/foo"), "malformed_token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeInspectHostedEnvelope(tc.input)
			var typed *inviteInspectError
			if !errors.As(err, &typed) || typed.Code != tc.code || typed.ExitCode() != 1 {
				t.Fatalf("incorrect safe error: %v", err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), tc.input) {
				t.Fatal("token leaked in parser error")
			}
		})
	}
	for _, input := range []string{"", "first\nsecond", strings.Repeat("a", inviteTokenStdinLimit+1)} {
		_, err := readInspectToken(strings.NewReader(input))
		if err == nil || exitCode(err) != 2 {
			t.Fatal("invalid stdin must be usage failure")
		}
	}
	data, _ := json.Marshal(map[string]string{"i": "fixture", "d": "example.test", "t": "backend", "s": secret, "a": "https://example.test/api"})
	controller := base64.RawURLEncoding.EncodeToString(data)
	decoded, err := decodeInspectControllerToken(controller)
	if err != nil || decoded.Domain != "example.test" || decoded.TeamName != "backend" || decoded.Secret != secret {
		t.Fatal("controller metadata did not decode")
	}
	bad, _ := json.Marshal(map[string]any{"s": secret, "d": []string{secret}})
	if _, err := decodeInspectControllerToken(base64.RawURLEncoding.EncodeToString(bad)); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("malformed controller error was missing or unsafe")
	}
	// Check raw output values, before JSON escaping can hide an echoed secret.
	echo, _ := json.Marshal(map[string]string{"i": "fixture", "d": "example.test", "t": "backend", "s": "secret&value", "a": "https://example.test/secret&value"})
	if result, err := inspectInvite(context.Background(), base64.RawURLEncoding.EncodeToString(echo)); err == nil || result != nil {
		t.Fatal("controller secret in routing metadata was not refused")
	}
}
