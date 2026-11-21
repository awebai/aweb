package awid

import (
	"context"
	"testing"
)

// awid is public Go API (cli/go/README.md "Go Library"). These are entry
// points as released in aw-v1.36.58; a change that breaks one fails to
// compile here (released-clients-are-a-permanent-constraint). aw-v1.36.58
// also exposed a comparable spawn request and its client signature.
var (
	_ map[SpawnAcceptInviteRequest]struct{}
	_ func(*Client, context.Context, *SpawnAcceptInviteRequest) (*SpawnAcceptInviteResponse, error)                                                                                                              = (*Client).AcceptSpawnInvite
	_ func(context.Context, VerificationStatus, string, string, string, string, *SenderMembership, *RotationAnnouncement, *ReplacementAnnouncement, *bool, ...ReceivedSenderBinding) (VerificationStatus, *bool) = (*Client)(nil).NormalizeReceivedSenderTrust
	_ func(string, *VerifiedLogHead)                                                                                                                                                                             = (*RegistryResolver)(nil).SeedVerifiedHead
)

// An anchor seeded through the released SeedVerifiedHead still refuses a
// valid but truncated log (the default-aajc.8 rollback) at the registry that
// later answers; a resolver with no anchor accepts that prefix, which is the
// control.
func TestReleasedSeedVerifiedHeadRefusesARollback(t *testing.T) {
	f := newDidLogRegistry(t)
	ctx := context.Background()
	resolverOf := func() *RegistryResolver { return f.newClient().resolver.(*RegistryResolver) }

	full := resolverOf().VerifyStableIdentity(ctx, didLogTestAddress, f.stableID)
	if full.Outcome != StableIdentityVerified || full.VerifiedHead == nil || full.VerifiedHead.Seq != 2 {
		t.Fatalf("full log: %+v", full)
	}
	*f.truncated = true

	if unanchored := resolverOf().VerifyStableIdentity(ctx, didLogTestAddress, f.stableID); unanchored.Outcome != StableIdentityVerified {
		t.Fatalf("control: an unanchored resolver did not accept the valid prefix: %+v", unanchored)
	}
	anchored := resolverOf()
	anchored.SeedVerifiedHead(f.stableID, full.VerifiedHead)
	if got := anchored.VerifyStableIdentity(ctx, didLogTestAddress, f.stableID); got.Outcome != StableIdentityHardError {
		t.Fatalf("a truncated log behind the released anchor was not refused: %+v", got)
	}
}

// The released SeedVerifiedHead advances a resolver that already holds a
// lower anchor of its own, as in aw-v1.36.58: the higher sequence is the
// floor. SeedVerifiedHeadAt stays scoped to its registry.
func TestReleasedSeedVerifiedHeadAdvancesAPopulatedResolver(t *testing.T) {
	f := newDidLogRegistry(t)
	ctx := context.Background()
	resolverOf := func() *RegistryResolver { return f.newClient().resolver.(*RegistryResolver) }

	full := resolverOf().VerifyStableIdentity(ctx, didLogTestAddress, f.stableID)
	if full.Outcome != StableIdentityVerified || full.VerifiedHead == nil || full.VerifiedHead.Seq != 2 {
		t.Fatalf("full log: %+v", full)
	}
	*f.truncated = true
	populated := resolverOf()
	first := populated.VerifyStableIdentity(ctx, didLogTestAddress, f.stableID)
	if first.Outcome != StableIdentityVerified || first.VerifiedHead == nil || first.VerifiedHead.Seq != 1 {
		t.Fatalf("the resolver did not take its own seq-1 anchor: %+v", first)
	}

	populated.SeedVerifiedHead(f.stableID, full.VerifiedHead)
	if got := populated.VerifyStableIdentity(ctx, didLogTestAddress, f.stableID); got.Outcome != StableIdentityHardError {
		t.Fatalf("the released seed did not advance the populated resolver past its seq-1 anchor: %+v", got)
	}

	// Scoped to another registry, the same head leaves this one alone.
	scoped := resolverOf()
	scoped.VerifyStableIdentity(ctx, didLogTestAddress, f.stableID)
	scoped.SeedVerifiedHeadAt("https://another-registry.example", f.stableID, full.VerifiedHead)
	if got := scoped.VerifyStableIdentity(ctx, didLogTestAddress, f.stableID); got.Outcome != StableIdentityVerified {
		t.Fatalf("a head seeded at another registry constrained this one: %+v", got)
	}
}
