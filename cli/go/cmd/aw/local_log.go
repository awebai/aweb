package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// localLogPolicy names the team whose owner log key, if any, a local log
// write seals to. It holds no decision: the installed record is resolved and
// verified at each write, under the team's policy lock, so a long-lived
// caller never acts on a record, or the absence of one, that has changed.
type localLogPolicy struct {
	sel *awconfig.Selection
}

func localLogPolicyForSelection(sel *awconfig.Selection) localLogPolicy {
	return localLogPolicy{sel: sel}
}

func (p localLogPolicy) teamID() string {
	if p.sel == nil {
		return ""
	}
	return strings.TrimSpace(p.sel.TeamID)
}

// resolvedLogKey is the policy's outcome now. With no record installed for
// the team the logs stay plaintext. An installed record that cannot be
// verified stops logging instead of falling back to plaintext.
type resolvedLogKey struct {
	record *awid.LogKeyRecord
	err    error
}

// resolve loads and verifies the team's installed record now.
func (p localLogPolicy) resolve() resolvedLogKey {
	teamID := p.teamID()
	if teamID == "" {
		return resolvedLogKey{}
	}
	rec, err := awconfig.LoadLogKeyRecord(teamID)
	if errors.Is(err, os.ErrNotExist) {
		return resolvedLogKey{}
	}
	if err != nil {
		return resolvedLogKey{err: err}
	}
	if err := verifyLogKeyRecordForSelection(p.sel, rec); err != nil {
		return resolvedLogKey{err: err}
	}
	return resolvedLogKey{record: rec}
}

// sealing reports whether the team has an owner log key installed now,
// usable or not; while it does, the agent does not read its logs back.
func (p localLogPolicy) sealing() bool {
	key := p.resolve()
	return key.record != nil || key.err != nil
}

// verifyLogKeyRecordForSelection accepts rec only when the selection's team
// key signed it: the key its own team certificate names, or for a grant seat,
// which holds no certificate, the key its grant recorded at mint.
func verifyLogKeyRecordForSelection(sel *awconfig.Selection, rec *awid.LogKeyRecord) error {
	teamDIDKey, err := logKeyVerificationTeamKey(sel)
	if err != nil {
		return err
	}
	if err := awid.VerifyLogKeyRecord(rec, sel.TeamID, teamDIDKey); err != nil {
		return fmt.Errorf("log key for team %s: %w", sel.TeamID, err)
	}
	return nil
}

func logKeyVerificationTeamKey(sel *awconfig.Selection) (string, error) {
	if awconfig.IsGrantHome(sel.IdentityHome) {
		grant, err := awconfig.LoadGrantHome(sel.IdentityHome)
		if err != nil {
			return "", fmt.Errorf("load the grant to verify the log key: %w", err)
		}
		return grantLogKeyTeamKey(grant, sel.TeamID)
	}
	cert, err := loadSelectedTeamCertificate(sel)
	if err != nil {
		return "", fmt.Errorf("load the team certificate to verify the log key: %w", err)
	}
	return cert.TeamDIDKey, nil
}

// grantLogKeyTeamKey is the team key a grant of teamID recorded at mint.
func grantLogKeyTeamKey(grant *awconfig.GrantHome, teamID string) (string, error) {
	if strings.TrimSpace(grant.TeamID) != strings.TrimSpace(teamID) {
		return "", fmt.Errorf("grant %s is for team %s, not %s", grant.GrantID, grant.TeamID, teamID)
	}
	if strings.TrimSpace(grant.TeamDIDKey) == "" {
		return "", fmt.Errorf("grant %s records no team key, so it cannot verify the team's owner log key; re-mint it with `aw id grant mint`", grant.GrantID)
	}
	return strings.TrimSpace(grant.TeamDIDKey), nil
}

// appendLocalLogLine appends entry, one JSON object, to path: sealed to the
// team's owner log key when one is installed, plaintext when the team has
// none. The policy is resolved while holding the team's policy lock, which
// installing a record also takes. Lines already in the file are never
// rewritten: a plaintext line carries no team, so it is not sealed to
// whichever team writes next. tagOf, when set, names the visible tag each
// sealed line carries.
func appendLocalLogLine(path string, policy localLogPolicy, entry []byte, tagOf func([]byte) string) error {
	if teamID := policy.teamID(); teamID != "" {
		policyLock, err := awconfig.LockLogKeyPolicy(teamID)
		if err != nil {
			return err
		}
		defer policyLock.Close()
	}
	key := policy.resolve()
	if key.err != nil {
		return fmt.Errorf("owner log key is unusable, not logging: %w", key.err)
	}
	line := entry
	if key.record != nil {
		var err error
		if line, err = sealLocalLogLine(key.record, entry, tagOf); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := awconfig.LockExclusive(path + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

func sealLocalLogLine(rec *awid.LogKeyRecord, plaintext []byte, tagOf func([]byte) string) ([]byte, error) {
	tag := ""
	if tagOf != nil {
		tag = tagOf(plaintext)
	}
	sealed, err := awid.SealLogLine(rec, tag, plaintext)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealed)
}

// sealedLogLineOf returns line as a sealed log line, or nil when it is not one.
func sealedLogLineOf(line []byte) *awid.SealedLogLine {
	var sealed awid.SealedLogLine
	if err := json.Unmarshal(line, &sealed); err != nil || sealed.Sealed == "" {
		return nil
	}
	return &sealed
}

func isSealedLogLine(line []byte) bool {
	return sealedLogLineOf(line) != nil
}

// readLocalLogLines returns the non-empty lines of a local log, the last
// limit of them when limit > 0.
func readLocalLogLines(path string, limit int) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lines = append(lines, append([]byte(nil), line...))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, nil
}
