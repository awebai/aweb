package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedInvitePreviewConnectionFailureRetainsItsAcceptanceMintedKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWEB_IDENTITY_HOME", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	home := filepath.Join(dir, ".aw")
	_, err = acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: dir, Token: "aw_inv_transport", Options: teamAcceptInviteOptions{IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal, AwebURL: origin}})
	if err == nil {
		t.Fatal("closed preview endpoint unexpectedly accepted the invitation")
	}
	key, readErr := os.ReadFile(filepath.Join(home, "signing.key"))
	if readErr != nil || len(key) == 0 {
		t.Fatalf("acceptance did not retain its minted key: %v", readErr)
	}
	marker := acceptanceMintedKey{Home: awconfig.IdentityHome{Root: home}}
	if present, markerErr := marker.present(); markerErr != nil || !present {
		t.Fatalf("acceptance-minted provenance missing: present=%v error=%v", present, markerErr)
	}
	if !retainUnfinishedProvisioningIdentity(fmt.Errorf("outer creation: %w", err)) {
		t.Fatalf("outer cleanup would discard the retained hosted key: %v", err)
	}
	var preview *inviteInspectError
	if !errors.As(err, &preview) || errorCodeOf(err) != preview.Code || err.Error() != preview.Error() {
		t.Fatalf("retention changed the original preview refusal: %v", err)
	}
	_, retryErr := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: dir, Token: "aw_inv_transport", Options: teamAcceptInviteOptions{IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal, AwebURL: origin}})
	if retryErr == nil || !retainUnfinishedProvisioningIdentity(retryErr) {
		t.Fatalf("retry lost the retained-key boundary: %v", retryErr)
	}
	after, readErr := os.ReadFile(filepath.Join(home, "signing.key"))
	if readErr != nil || !bytes.Equal(key, after) {
		t.Fatal("retry replaced the original recipient key")
	}
}

func TestHostedInviteUnreadableRecoveryKeepsItsOriginalRecipientAndFailure(t *testing.T) {
	for _, fixture := range []struct {
		Name      string
		File      string
		Directory bool
	}{
		{Name: "malformed journal", File: hostedInviteRecoveryFile},
		{Name: "unreadable journal", File: hostedInviteRecoveryFile, Directory: true},
		{Name: "malformed marker", File: acceptanceKeyMarkerName},
		{Name: "unreadable marker", File: acceptanceKeyMarkerName, Directory: true},
	} {
		t.Run(fixture.Name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AWEB_IDENTITY_HOME", "")
			dir := t.TempDir()
			home := filepath.Join(dir, ".aw")
			if _, _, err := hostedAcceptSigningKeyAt(dir, home); err != nil {
				t.Fatal(err)
			}
			key, err := os.ReadFile(filepath.Join(home, "signing.key"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, fixture.File)
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if fixture.Directory {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("malformed recovery\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: dir, Token: "aw_inv_recovery", Options: teamAcceptInviteOptions{IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal}})
			if err == nil || !retainUnfinishedProvisioningIdentity(fmt.Errorf("outer creation: %w", err)) {
				t.Fatalf("unreadable hosted recovery authorized outer key removal: %v", err)
			}
			after, readErr := os.ReadFile(filepath.Join(home, "signing.key"))
			if readErr != nil || !bytes.Equal(key, after) {
				t.Fatal("recovery failure replaced its recipient key")
			}
		})
	}
}

func TestHostedInvitePreKeyRefusalDoesNotInventRetainedRecovery(t *testing.T) {
	t.Setenv("AWEB_IDENTITY_HOME", "")
	dir := t.TempDir()
	home := filepath.Join(dir, ".aw")
	_, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: dir, Token: "aw_inv_unused", Options: teamAcceptInviteOptions{IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal, NoAddress: true}})
	if err == nil || retainUnfinishedProvisioningIdentity(err) || err.Error() != "--no-address requires --global" {
		t.Fatalf("pre-key refusal changed or invented recovery state: %v", err)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-key refusal created its recipient home: %v", err)
	}
}
