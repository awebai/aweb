package main

import (
	"context"
	"github.com/awebai/aw/awid"
	"strings"
	"testing"
)

func TestOnlineDoctorSeparatesCurrentSupersededAndUnknownMembership(t *testing.T) {
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert := signedMemberCertificate(t, teamKey, awid.ComputeDIDKey(memberPublic), "", awid.IdentityModeLocal)
	registry := newCertificateRegistry(t, teamKey)
	registry.register(cert, false)
	request := installRequest(t, registry, t.TempDir(), certificateFile(t, cert))
	input := awid.CurrentTeamCertificateCheck{RegistryURL: request.RegistryURL, Certificate: cert}
	current := doctorCurrentTeamCertificate(context.Background(), request.Registry, input)
	if current.Status != doctorStatusOK || !strings.Contains(current.Message, "certificate is current") {
		t.Fatalf("current: %+v", current)
	}
	registry.mu.Lock()
	registry.teamKey = "did:key:superseding-team"
	registry.mu.Unlock()
	superseded := doctorCurrentTeamCertificate(context.Background(), request.Registry, input)
	if superseded.Status != doctorStatusFail || !strings.Contains(superseded.Message, "team key this agent was given does not match the registry's") || !strings.Contains(superseded.NextStep, "current certificate") {
		t.Fatalf("superseded: %+v", superseded)
	}
	registry.mu.Lock()
	registry.down = true
	registry.mu.Unlock()
	unknown := doctorCurrentTeamCertificate(context.Background(), request.Registry, input)
	if unknown.Status != doctorStatusUnknown || !strings.Contains(unknown.Message, registry.server.URL) || !strings.Contains(unknown.Message, "unknown") || !strings.Contains(unknown.NextStep, "retry aw doctor --online") {
		t.Fatalf("unknown: %+v", unknown)
	}
}
