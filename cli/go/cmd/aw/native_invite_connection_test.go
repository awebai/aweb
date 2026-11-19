package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// A failed connection is real transport evidence, not a registry refusal.
// Acceptance must retain its prepared certificate instead of exposing a fresh
// bearer after an outcome it could not establish.
func TestOATSNativeInviteConnectionFailureRetainsTheExactAttempt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AWEB_IDENTITY_HOME", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	registryURL := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	_, controller, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "one", controller); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "recipient", ".aw")
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{InviteID: "connection-attempt", Domain: "example.com", TeamName: "one", IdentityScope: awid.IdentityModeLocal, Secret: "bearer-retained-privately", RegistryURL: registryURL, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	// Routing fields in the unsigned bearer cannot replace the saved selection.
	modified := *invite
	modified.RegistryURL = "http://127.0.0.1:1"
	token, err := awconfig.EncodeInviteToken(&modified)
	if err != nil {
		t.Fatal(err)
	}
	_, acceptErr := acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: dir,
		Token:      token,
		Options:    teamAcceptInviteOptions{IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal},
	})
	if acceptErr == nil {
		t.Fatal("unavailable registry unexpectedly accepted membership")
	}
	saved, err := awconfig.LoadTeamInvite(invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	// Use the serialized public progress vocabulary so this behavioral
	// regression also compiles against the unfenced acceptance implementation.
	var record struct {
		Secret     string `json:"secret"`
		ConsumedAt string `json:"consumed_at"`
		Issuance   *struct {
			State   string `json:"state"`
			Context struct {
				IdentityHome string `json:"identity_home"`
				RegistryURL  string `json:"registry_url"`
			} `json:"context"`
			Effect awid.TeamCertificate `json:"prepared_effect"`
		} `json:"issuance"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Issuance == nil || record.Issuance.State != "attempted" || record.Secret != "" || record.ConsumedAt != "" {
		t.Fatalf("transport failure exposed an unused invite instead of retaining an exact attempted issuance: %v", acceptErr)
	}
	if record.Issuance.Context.IdentityHome != home || record.Issuance.Context.RegistryURL != registryURL || record.Issuance.Effect.Alias != "recipient" || record.Issuance.Effect.CertificateID == "" {
		t.Fatal("attempt lost its exact recipient, registry or certificate")
	}
	if err := awid.VerifyTeamCertificate(&record.Issuance.Effect, controller.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	// The provisioning driver receives a wrapped error. It must see the retained
	// fence before deciding whether it may discard this recipient's credentials.
	if !retainUnfinishedProvisioningIdentity(fmt.Errorf("provisioning acceptance: %w", acceptErr)) {
		t.Fatalf("retained native issuance did not protect its recipient through outer cleanup: %v", acceptErr)
	}
	var transport *net.OpError
	if !errors.As(acceptErr, &transport) || errorCodeOf(acceptErr) != "invite_issuance_pending" {
		t.Fatalf("retention wrapper changed the original transport cause or public code: %v", acceptErr)
	}
}
