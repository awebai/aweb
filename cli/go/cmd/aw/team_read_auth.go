package main

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Signed reads of a private team.
//
// The registry gates team reads on visibility (awid_service/routes/teams.py
// _require_team_read_access): a team not marked public is readable only by the
// trusted service token, by the team controller key, or by a key holding an
// unrevoked membership certificate in the team - proven with the same
// path-signature the certificate blob fetch already uses. The helpers here
// answer the two questions the CLI side of that needs: which locally held keys
// could authorize this read, and what to say when none of them did.

// teamReadSigners returns the locally available keys that may authorize a
// signed registry read of domain/team, in the order they should be tried:
//
//  1. the invoking workspace's own identity signing key - the common case, an
//     agent reading the team it is a member of. The registry admits any key
//     holding an unrevoked membership certificate in the team;
//  2. a locally held team controller key - the BYOT controller operating on its
//     own team from a directory whose identity is not itself a member. A hosted
//     namespace never has local controller custody, so it contributes no
//     candidate there.
//
// An empty result means the read goes out unsigned, which is the pre-visibility
// behavior byte for byte and is all a public team needs.
func teamReadSigners(workingDir, domain, team string) []ed25519.PrivateKey {
	return teamReadSignersForKeyPath(identitySigningKeyPathForDir(workingDir), domain, team)
}

// teamReadSignersForKeyPath is teamReadSigners for callers that already resolved
// the identity signing key path - a selection carries one, and it accounts for
// --identity-home and the active team, so re-deriving it from the working
// directory could pick a different identity than the command is acting as.
func teamReadSignersForKeyPath(signingKeyPath, domain, team string) []ed25519.PrivateKey {
	var signers []ed25519.PrivateKey
	if path := strings.TrimSpace(signingKeyPath); path != "" {
		if key, err := awid.LoadSigningKey(path); err == nil {
			signers = append(signers, key)
		}
	}
	if !isAwebHostedNamespace(domain) {
		if exists, err := awconfig.TeamKeyExists(domain, team); err == nil && exists {
			if key, err := awconfig.LoadTeamKey(domain, team); err == nil && !containsSigningKey(signers, key) {
				signers = append(signers, key)
			}
		}
	}
	return signers
}

func identitySigningKeyPathForDir(workingDir string) string {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return ""
	}
	// IdentityHomePath, rather than a join: it is the boundary that keeps an
	// identity-home path from escaping its home through a symlink.
	path, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return ""
	}
	return path
}

func containsSigningKey(keys []ed25519.PrivateKey, candidate ed25519.PrivateKey) bool {
	for _, key := range keys {
		if key.Equal(candidate) {
			return true
		}
	}
	return false
}

// readSignedTeamState runs read once per candidate key, in order, and returns
// the key it succeeded with - nil when the read went out unsigned - so a second
// read of the same team can reuse it instead of walking the candidates again.
//
// Only the registry's visibility refusal advances to the next candidate. Every
// other error is returned as it arrives: a 404, a timeout or a 500 says nothing
// about credentials, and retrying it under a different key would turn one
// failed read into several and report the last one.
func readSignedTeamState(
	signers []ed25519.PrivateKey,
	read func(ed25519.PrivateKey) error,
) (ed25519.PrivateKey, error) {
	if len(signers) == 0 {
		return nil, read(nil)
	}
	var lastErr error
	for _, key := range signers {
		err := read(key)
		if err == nil {
			return key, nil
		}
		if !awid.IsTeamPrivateError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// friendlyTeamReadError converts the registry's team_private refusal into a
// message the operator can act on; every other error passes through unchanged,
// so callers can compare the result against what they passed in to tell the two
// apart. The raw 403 body is deliberately dropped: the code has been
// recognized, and repeating the HTTP exchange adds nothing actionable.
//
// signed says whether the refused read carried a signature at all, because the
// two arrivals need different remedies: an unsigned read needs credentials to
// exist here, a signed one needs different credentials than the ones that were
// tried.
func friendlyTeamReadError(err error, teamID string, signed bool) error {
	if err == nil || !awid.IsTeamPrivateError(err) {
		return err
	}
	teamID = strings.TrimSpace(teamID)
	if signed {
		return fmt.Errorf(
			"team %s is private, and no signing key available here is authorized to read it: none is the team controller key and none holds an unrevoked membership certificate in the team. Run this from a workspace holding a certificate for this team, or ask the team controller - team visibility is controller-set",
			teamID,
		)
	}
	return fmt.Errorf(
		"team %s is private, and no signing credentials for it were found here, so the registry refused the unsigned read. Run this from a workspace holding a certificate for this team, or ask the team controller - team visibility is controller-set",
		teamID,
	)
}
