package awconfig

import (
	"errors"
	"time"
)

const (
	// DefaultTeamInviteLifetime matches the hosted invitation default.
	DefaultTeamInviteLifetime = 24 * time.Hour
	// MaximumTeamInviteLifetime bounds a newly issued local invitation.
	MaximumTeamInviteLifetime = 30 * 24 * time.Hour
)

// TeamInviteLifetimeRequest fixes the issuance clock and requested duration.
// A zero duration selects the default; the clock must be explicit.
type TeamInviteLifetimeRequest struct {
	Now      time.Time
	Duration time.Duration
}

// TeamInviteLifetime contains the issuer-owned creation and expiry times.
type TeamInviteLifetime struct {
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ErrTeamInviteLifetime refuses invalid or unreadable lifetime evidence without
// including any of the private invitation's contents in a diagnostic.
var ErrTeamInviteLifetime = errors.New("local invitation lifetime is invalid; issue a new invite with aw id team invite")

// ResolveTeamInviteLifetime applies the one local lifetime policy documented in
// docs/identity.md:24-hour default, no more than 30 days. A token never supplies
// this lifetime; it is fixed before the issuer stores or publishes its grant.
func ResolveTeamInviteLifetime(input TeamInviteLifetimeRequest) (TeamInviteLifetime, error) {
	if input.Now.IsZero() {
		return TeamInviteLifetime{}, ErrTeamInviteLifetime
	}
	duration := input.Duration
	if duration == 0 {
		duration = DefaultTeamInviteLifetime
	}
	if duration < 0 || duration > MaximumTeamInviteLifetime {
		return TeamInviteLifetime{}, ErrTeamInviteLifetime
	}
	created := input.Now.UTC()
	return TeamInviteLifetime{CreatedAt: created, ExpiresAt: created.Add(duration)}, nil
}

// TeamInviteLifecycleState distinguishes an unused bearer from an unresolved
// remote attempt or a confirmed issued membership, independently of its age.
type TeamInviteLifecycleState string

const (
	TeamInviteUnknown   TeamInviteLifecycleState = "unknown"
	TeamInviteUnused    TeamInviteLifecycleState = "unused"
	TeamInviteAttempted TeamInviteLifecycleState = "attempted"
	TeamInviteConsumed  TeamInviteLifecycleState = "consumed"
	TeamInviteExpired   TeamInviteLifecycleState = "expired"
)

// TeamInviteLifecycleRequest names the saved issuer record and inspection clock.
type TeamInviteLifecycleRequest struct {
	Invite *TeamInvite
	Now    time.Time
}

// TeamInviteLifecycle reports public progress and authoritative lifetime. Times
// remain zero when an unresolved or confirmed effect takes precedence over age.
type TeamInviteLifecycle struct {
	State     TeamInviteLifecycleState
	CreatedAt time.Time
	ExpiresAt time.Time
}

// InspectTeamInviteLifecycle is read-only. Per docs/cli-integration-contract.md,
// attempted/unknown issuance is inspected before expiry: an old uncertain effect
// never becomes an unused grant. Released records without expires_at receive
// CreatedAt plus the default; unreadable evidence is unknown and refuses.
func InspectTeamInviteLifecycle(input TeamInviteLifecycleRequest) (TeamInviteLifecycle, error) {
	unknown := TeamInviteLifecycle{State: TeamInviteUnknown}
	issuance, err := InspectTeamInviteIssuance(input.Invite)
	if err != nil {
		return unknown, err
	}
	if issuance != nil {
		switch issuance.State {
		case RecoveryAttempted:
			return TeamInviteLifecycle{State: TeamInviteAttempted}, nil
		case RecoveryConfirmed:
			return TeamInviteLifecycle{State: TeamInviteConsumed}, nil
		default:
			return unknown, ErrInviteIssuanceUnknown
		}
	}
	if input.Invite.ConsumedAt != "" {
		return TeamInviteLifecycle{State: TeamInviteConsumed}, nil
	}
	if input.Now.IsZero() {
		return unknown, ErrTeamInviteLifetime
	}
	created, err := time.Parse(time.RFC3339Nano, input.Invite.CreatedAt)
	if err != nil {
		return unknown, ErrTeamInviteLifetime
	}
	lifetime, err := ResolveTeamInviteLifetime(TeamInviteLifetimeRequest{Now: created})
	if err != nil {
		return unknown, err
	}
	if input.Invite.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, input.Invite.ExpiresAt)
		if err != nil || !expires.After(created) || expires.After(created.Add(MaximumTeamInviteLifetime)) {
			return unknown, ErrTeamInviteLifetime
		}
		lifetime.ExpiresAt = expires
	}
	state := TeamInviteUnused
	if !input.Now.Before(lifetime.ExpiresAt) {
		state = TeamInviteExpired
	}
	return TeamInviteLifecycle{State: state, CreatedAt: lifetime.CreatedAt, ExpiresAt: lifetime.ExpiresAt}, nil
}
