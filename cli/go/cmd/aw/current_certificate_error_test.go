package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// This is a local HTTP error-adapter control, not registry authority proof.
// The actual signed-registry fetch regression retains the same wire assertion.
func TestWrappedSDKCertificateRefusalKeepsItsCLIJSONCode(t *testing.T) {
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	certificate := signedMemberCertificate(t, teamKey, awid.ComputeDIDKey(memberPublic), "", awid.IdentityModeLocal)
	registry := newCertificateRegistry(t, teamKey)
	registry.register(certificate, false)
	request := installRequest(t, registry, t.TempDir(), certificateFile(t, certificate))
	input := awid.CurrentTeamCertificateCheck{RegistryURL: request.RegistryURL, Certificate: certificate}
	if err := request.Registry.CheckCurrentTeamCertificate(context.Background(), input); err != nil {
		t.Fatalf("current certificate floor: %v", err)
	}
	nextPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	registry.teamKey = awid.ComputeDIDKey(nextPublic)
	registry.mu.Unlock()
	refused := request.Registry.CheckCurrentTeamCertificate(context.Background(), input)
	var typed *awid.CurrentTeamCertificateError
	if !errors.As(refused, &typed) || typed.Code != awid.CurrentCertificateKeyChanged {
		t.Fatalf("SDK refusal: %v", refused)
	}
	wrapped := fmt.Errorf("fetch certificate: %w", refused)
	if code := errorCodeOf(wrapped); code != "team_key_not_current" {
		t.Fatalf("wrapped SDK code=%q, want team_key_not_current", code)
	}
	envelope := errorEnvelope(wrapped, wrapped.Error())
	if envelope.Error.Code != "team_key_not_current" || !strings.Contains(envelope.Error.Message, "ask the team's owner") {
		t.Fatalf("JSON refusal lost code or next action: %+v", envelope.Error)
	}
}
