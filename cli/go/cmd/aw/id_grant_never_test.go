package main

import (
	"context"
	"crypto/ed25519"
	"github.com/awebai/aw/awid"
	"strings"
	"testing"
	"time"
)

func TestGrantTTLNeverFlag(t *testing.T) {
	resetGrantCommandGlobals(t)
	mint, _, err := rootCmd.Find([]string{"id", "grant", "mint"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mint.Flags().Set("ttl", "never"); err != nil {
		t.Fatalf("never must parse: %v", err)
	}
	if grantMintTTL >= 0 {
		t.Fatal("never must have a distinct marker")
	}
	if err := mint.Flags().Set("ttl", "8h"); err != nil || grantMintTTL != 8*time.Hour {
		t.Fatal("finite duration changed")
	}
	if err := mint.Flags().Set("ttl", "nonsense"); err == nil {
		t.Fatal("malformed TTL accepted")
	}
}

func TestNeverGrantCustodyCapabilityAndExpiry(t *testing.T) {
	if err := requireNeverGrantCustody([]string{"status.v1"}); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("old host must give actionable error: %v", err)
	}
	if err := requireNeverGrantCustody([]string{"grant_never_ttl.v1"}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "null", "nonsense"} {
		if checkGrantExpiry(raw, time.Now()) == nil {
			t.Fatalf("invalid expiry accepted %q", raw)
		}
	}
	if err := checkGrantExpiry("never", time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	_, resident, _ := ed25519.GenerateKey(nil)
	_, session, _ := ed25519.GenerateKey(nil)
	svc := testCustodyService(t, resident, session)
	req := signedCustodyRequest(t, session, awid.ComputeDIDKey(resident.Public().(ed25519.PublicKey)))
	st := custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: req.TeamID, GrantDIDKey: req.SessionDIDKey, Scopes: []string{"mail.send"}, ExpiresAt: "never"}
	svc.grantStatus = func(context.Context, string) (custodyGrantStatus, error) { return st, nil }
	if _, err := svc.signPlainMessage(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	st.Active = false
	st.EffectiveStatus = "revoked"
	// Use a fresh request so replay handling cannot mask current authorization.
	req = signedCustodyRequest(t, session, awid.ComputeDIDKey(resident.Public().(ed25519.PublicKey)))
	if _, err := svc.signPlainMessage(context.Background(), req); err == nil || !strings.Contains(err.Error(), "grant_revoked") {
		t.Fatalf("revocation must win: %v", err)
	}
	status := svc.status(context.Background(), "running", nil)
	if err := requireNeverGrantCustody(status.Ops); err != nil {
		t.Fatal(err)
	}
}
