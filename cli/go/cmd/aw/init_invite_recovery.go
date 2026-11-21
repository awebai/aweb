package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const initInviteRecoveryFile = "init-invite.json"

// Private: Token is a bearer credential and must never appear in diagnostics.
type initInviteRecovery struct {
	Roster           bool   `json:"roster,omitempty"`
	ParentFromSource bool   `json:"parent_from_source"`
	MintedKey        bool   `json:"minted_key"`
	Source           string `json:"source"`
	SourceHome       string `json:"source_home"`
	TeamID           string `json:"team_id"`
	Alias            string `json:"alias"`
	Scope            string `json:"scope"`
	Token            string `json:"token"`
	Origin           string `json:"origin"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	DIDKey           string `json:"did_key,omitempty"`
}

func (s *initInviteRecovery) save(path string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).Write(raw)
}

func loadInitInviteRecovery(path string) (*initInviteRecovery, error) {
	raw, err := (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).Read()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s initInviteRecovery
	if json.Unmarshal(raw, &s) != nil || s.TeamID == "" || (!s.Roster && s.Token == "") ||
		(s.Roster && (s.Scope != awid.IdentityModeGlobal || s.DIDKey == "")) {
		return nil, errors.New("invalid init invite recovery")
	}
	return &s, nil
}

func (s *initInviteRecovery) matchesSelection(other initInviteRecovery) bool {
	return s.Source == other.Source && s.SourceHome == other.SourceHome &&
		s.TeamID == other.TeamID && s.Alias == other.Alias && s.Scope == other.Scope
}

func (s *initInviteRecovery) matchesKey(home string) bool {
	path, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: home}, "signing.key")
	if err != nil {
		return false
	}
	key, err := awid.LoadSigningKey(path)
	return err == nil && didOf(key) == s.DIDKey
}

func runRecoverableJoinFrom(cmd *cobra.Command, wd, joinFrom, joinTeam string) error {
	home, err := identityHomeForTarget(wd, "")
	if err != nil {
		return err
	}
	path := filepath.Join(home.Root, initInviteRecoveryFile)
	scope := initInviteIdentityScope()
	_, recordErr := os.Stat(path)
	newSelection := errors.Is(recordErr, os.ErrNotExist)
	if recordErr != nil && !newSelection {
		return recordErr
	}
	if newSelection && home.External() {
		if err := validateNewInitJoinTarget(wd, home, scope); err != nil {
			return err
		}
	}
	source, sourceHome, team, err := resolveInitJoinSource(joinFrom, joinTeam)
	if err != nil {
		return err
	}
	if newSelection && scope == awid.IdentityModeGlobal {
		// A source is an explicit parent choice only for a chainless joiner.
		// Refuse an impossible choice before even creating the recovery lock.
		if err := validateGlobalInitTarget(wd); err != nil {
			return err
		}
		installed, err := awconfig.LoadInstalledIDChain(home.Root)
		if err != nil {
			return err
		}
		if installed == nil {
			issuer, err := resolveIDExchangeIdentity(source, sourceHome)
			if err != nil {
				return err
			}
			if strings.HasPrefix(identityID(issuer), "did:key:") {
				return unregisteredInviteParentError()
			}
		}
	}
	_, homeErr := os.Stat(home.Root)
	lock, err := awconfig.TryLockExclusive(path + ".lock")
	if err != nil {
		return fmt.Errorf("init join could not acquire its recovery lock: %w", err)
	}
	defer func() {
		lock.Close()
		if errors.Is(homeErr, os.ErrNotExist) {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				if _, err := os.Stat(filepath.Join(home.Root, "signing.key")); errors.Is(err, os.ErrNotExist) {
					_ = os.Remove(path + ".lock")
					_ = os.Remove(home.Root) // Only succeeds if no other state was written.
				}
			}
		}
	}()
	prior, err := loadInitInviteRecovery(path)
	if err != nil {
		return err
	}
	alias := resolveAliasValue(resolveInitLocalName())
	if prior != nil {
		if prior.Roster {
			return usageError("this identity has a pending roster invitation; rerun the original aw team admin add or extend command")
		}
		if !prior.matchesSelection(initInviteRecovery{Source: source, SourceHome: sourceHome, TeamID: team, Alias: alias, Scope: scope}) {
			return errors.New("init retry changed the original source, team, name or scope")
		}
		if prior.DIDKey != "" && !prior.matchesKey(home.Root) {
			return errors.New("init retry child key changed")
		}
	} else {
		if err := validateNewInitJoinTarget(wd, home, scope); err != nil {
			return err
		}
		_, keyErr := os.Stat(filepath.Join(home.Root, "signing.key"))
		if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
			return keyErr
		}
		invite, err := createWorkspaceTeamInviteForTeamAt(source, sourceHome, team, scope)
		if err != nil {
			return withErrorCode(codeInviteNotCreated, fmt.Errorf("%w; alternatively use --admission-team-id %s with host authorization", err, team))
		}
		prior = &initInviteRecovery{MintedKey: errors.Is(keyErr, os.ErrNotExist), Source: source, SourceHome: sourceHome, TeamID: team, Alias: alias, Scope: scope, Token: invite.Token, Origin: invite.AwebURL, ExpiresAt: invite.ExpiresAt}
		if err := prior.save(path); err != nil {
			return err
		}
	}
	// The retained source is an explicit parent choice, even on older records.
	if !prior.ParentFromSource {
		prior.ParentFromSource = true
		if err := prior.save(path); err != nil {
			return err
		}
	}
	// Membership may already have been persisted before connect failed.
	cert, err := loadTeamCertificateAt(wd, home.Root, team)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load init retry membership: %w", err)
	}
	if cert != nil {
		bindKey := prior.DIDKey == ""
		if bindKey {
			key, err := awid.LoadSigningKey(filepath.Join(home.Root, "signing.key"))
			if err != nil {
				return fmt.Errorf("load init retry child key: %w", err)
			}
			prior.DIDKey = awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		}
		if cert.MemberDIDKey != prior.DIDKey {
			return errors.New("init retry membership key changed")
		}
		if bindKey {
			if err := prior.save(path); err != nil {
				return err
			}
		}
		if err := connectInitAcceptedInvite(cmd, wd, prior.Origin, home); err != nil {
			return err
		}
		return removeInitInviteRecovery(path)
	}
	recoveryPath := filepath.Join(home.Root, hostedInviteRecoveryFile)
	pending, err := loadHostedInviteCreation(recoveryPath)
	if err != nil {
		return err
	}
	uncertain := pending != nil && (pending.AcceptAttempted == nil || *pending.AcceptAttempted || pending.ResponseJSON != "")
	if prior.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, prior.ExpiresAt)
		if err != nil {
			return errors.New("invalid saved invite expiry")
		}
		if !time.Now().Before(expiry) {
			if uncertain {
				return uncertainHostedInviteError(home.Root, team, errors.New("invite expired"))
			}
			if err := discardHostedInviteAttempt(recoveryPath); err != nil {
				return err
			}
			if err := releaseInitInviteRecovery(path, wd, home.Root); err != nil {
				return err
			}
			return errors.New("invite expired; pending selection released, retry init for a new invite")
		}
	}
	err = acceptInitInviteAndConnect(cmd, initInviteConnection{WorkingDir: wd, IdentityHome: externalIdentityHomeRoot(home), Token: prior.Token, PreferredAwebURL: prior.Origin, ParentFromSource: prior.ParentFromSource})
	// Save the generated child binding even when preview or acceptance failed.
	if key, keyErr := awid.LoadSigningKey(filepath.Join(home.Root, "signing.key")); keyErr == nil {
		prior.DIDKey = awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		if saveErr := prior.save(path); saveErr != nil {
			return errors.Join(err, saveErr)
		}
	}
	if err == nil {
		return removeInitInviteRecovery(path)
	}
	if !uncertain && hostedInviteDefinitiveRefusal(err) {
		return errors.Join(err, releaseInitInviteRecovery(path, wd, home.Root))
	}
	return err
}

func removeInitInviteRecovery(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("failed to remove completed init invite recovery")
	}
	return nil
}

func uncertainHostedInviteError(home, team string, cause error) error {
	domain, name, _ := awid.ParseTeamID(team)
	return fmt.Errorf("%w; the earlier attempt may have succeeded. State is kept in %s. Check with the hosting service whether this agent is a member. If it is, obtain its certificate ID and run aw --identity-home %s id team fetch-cert --namespace %s --team %s --cert-id <certificate-id>, then retry init. If it is not, with no join running remove %s and %s before using a correct invite", cause, filepath.Join(home, hostedInviteRecoveryFile), shellQuote(home), domain, name, filepath.Join(home, hostedInviteRecoveryFile), filepath.Join(home, initInviteRecoveryFile))
}

// Shared closed pre-effect refusals. Status alone never proves no effect.
func hostedInviteDefinitiveRefusal(err error) bool {
	if awid.IDCertificateErrorCode(err) == "human_mismatch" {
		return true
	}
	status, ok := awid.HTTPStatusCode(err)
	if !ok || status < 400 || status >= 500 {
		return false
	}
	switch strings.TrimSpace(awid.RefusalCode(err)) {
	case "human_condition_mismatch":
		return status == 409
	}
	return false
}

// A definitively abandoned init retains only its generated identity, not its
// operation selection. The existing private key marker permits a correct invite.
func releaseInitInviteRecovery(path, wd, home string) error {
	state, err := loadInitInviteRecovery(path)
	if err != nil {
		return err
	}
	if state != nil && state.MintedKey {
		if _, err := os.Stat(filepath.Join(home, "signing.key")); err == nil {
			if err := (acceptanceMintedKey{Home: awconfig.IdentityHome{Root: home}}).save(); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return removeInitInviteRecovery(path)
}

// Recheck under the recovery lock before minting. The early call names a
// dirty explicit target before looking at the source or creating the lock.
func validateNewInitJoinTarget(wd string, home awconfig.IdentityHome, scope string) error {
	released, err := releasedInitTarget(wd, home)
	if err != nil {
		return err
	}
	if released && scope != awid.IdentityModeGlobal {
		return nil
	}
	if home.External() {
		return ensureIdentityCreationTargetClean(home)
	}
	return ensureInitInviteTarget(wd)
}

func releasedInitTarget(wd string, home awconfig.IdentityHome) (bool, error) {
	if strings.TrimSpace(home.Root) == "" {
		return false, errors.New("released init requires an explicit identity home")
	}
	for _, name := range []string{hostedInviteRecoveryFile, "grant.yaml", "teams.yaml", "workspace.yaml"} {
		if _, err := os.Stat(filepath.Join(home.Root, name)); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	if _, err := os.Stat(filepath.Join(home.Root, "signing.key")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	present, err := (acceptanceMintedKey{Home: home}).present()
	if err != nil || !present {
		return false, err
	}
	if _, _, err := hostedAcceptSigningKeyAt(wd, home.Root); err != nil {
		return false, err
	}
	return true, nil
}
