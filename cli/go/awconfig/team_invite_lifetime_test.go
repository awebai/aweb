package awconfig

import (
	"testing"
	"time"
)

func TestTeamInviteLifetimeDefaultsAndUpperBound(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name           string
		duration, want time.Duration
		refused        bool
	}{
		{name: "default", want: 24 * time.Hour},
		{name: "longer", duration: 72 * time.Hour, want: 72 * time.Hour},
		{name: "maximum", duration: 30 * 24 * time.Hour, want: 30 * 24 * time.Hour},
		{name: "too long", duration: 30*24*time.Hour + time.Second, refused: true},
		{name: "negative", duration: -time.Second, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			life, err := ResolveTeamInviteLifetime(TeamInviteLifetimeRequest{Now: now, Duration: tc.duration})
			if tc.refused {
				if err == nil {
					t.Fatal("invalid duration accepted")
				}
				return
			}
			if err != nil || !life.CreatedAt.Equal(now) || !life.ExpiresAt.Equal(now.Add(tc.want)) {
				t.Fatalf("life=%+v err=%v", life, err)
			}
		})
	}
}

func TestTeamInviteLifecycleUsesSavedExpiryIncludingReleasedRecords(t *testing.T) {
	created := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, expires string
		now           time.Time
		want          TeamInviteLifecycleState
		invalid       bool
	}{
		{name: "released live", now: created.Add(24*time.Hour - time.Nanosecond), want: TeamInviteUnused},
		{name: "released expires at boundary", now: created.Add(24 * time.Hour), want: TeamInviteExpired},
		{name: "saved longer", expires: created.Add(72 * time.Hour).Format(time.RFC3339), now: created.Add(25 * time.Hour), want: TeamInviteUnused},
		{name: "saved expiry", expires: created.Add(time.Hour).Format(time.RFC3339), now: created.Add(2 * time.Hour), want: TeamInviteExpired},
		{name: "malformed", expires: "unreadable", now: created, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invite := &TeamInvite{CreatedAt: created.Format(time.RFC3339), ExpiresAt: tc.expires, Secret: "private-bearer"}
			state, err := InspectTeamInviteLifecycle(TeamInviteLifecycleRequest{Invite: invite, Now: tc.now})
			if tc.invalid {
				if err == nil || state.State != TeamInviteUnknown {
					t.Fatal("malformed expiry became unused")
				}
				return
			}
			if err != nil || state.State != tc.want {
				t.Fatalf("state=%+v err=%v", state, err)
			}
			if invite.Secret != "private-bearer" || invite.ExpiresAt != tc.expires {
				t.Fatal("inspection changed the saved record")
			}
		})
	}
}

func TestTeamInviteLifecyclePreservesAttemptedAndConsumedBeforeExpiry(t *testing.T) {
	// The real issuance tests construct a signed fence through the sole writer.
	input := prepareInviteIssuanceTest(t)
	if err := BeginTeamInviteIssuance(input); err != nil {
		t.Fatal(err)
	}
	attempted, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := InspectTeamInviteLifecycle(TeamInviteLifecycleRequest{Invite: attempted, Now: time.Now().Add(365 * 24 * time.Hour)})
	if err != nil || before.State != TeamInviteAttempted {
		t.Fatalf("attempted became expired: %+v %v", before, err)
	}
	if err := ConfirmTeamInviteIssuance(TeamInviteIssuanceOutcomeInput{InviteID: input.InviteID, CertificateID: input.Certificate.CertificateID, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	consumed, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	after, err := InspectTeamInviteLifecycle(TeamInviteLifecycleRequest{Invite: consumed, Now: time.Now().Add(365 * 24 * time.Hour)})
	if err != nil || after.State != TeamInviteConsumed {
		t.Fatalf("consumed became expired: %+v %v", after, err)
	}
	attempted.Issuance.Version = 99
	unknown, err := InspectTeamInviteLifecycle(TeamInviteLifecycleRequest{Invite: attempted, Now: time.Now()})
	if err == nil || unknown.State != TeamInviteUnknown {
		t.Fatal("unknown issuance became unused")
	}
}
