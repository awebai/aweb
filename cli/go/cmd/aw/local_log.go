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
	"github.com/awebai/aw/internal/atomicfile"
)

// localLogKey is the owner log key a local log write seals to. With no
// record installed for the team the logs stay plaintext. An installed record
// that cannot be verified stops logging instead of falling back to plaintext.
type localLogKey struct {
	record *awid.LogKeyRecord
	err    error
}

// sealing reports whether the team has an owner log key installed, usable or
// not; while it does, the agent does not read its logs back.
func (k localLogKey) sealing() bool {
	return k.record != nil || k.err != nil
}

func localLogKeyForSelection(sel *awconfig.Selection) localLogKey {
	if sel == nil || strings.TrimSpace(sel.TeamID) == "" {
		return localLogKey{}
	}
	rec, err := awconfig.LoadLogKeyRecord(sel.TeamID)
	if errors.Is(err, os.ErrNotExist) {
		return localLogKey{}
	}
	if err != nil {
		return localLogKey{err: err}
	}
	if err := verifyLogKeyRecordForSelection(sel, rec); err != nil {
		return localLogKey{err: err}
	}
	return localLogKey{record: rec}
}

// verifyLogKeyRecordForSelection accepts rec only when the team key named by
// the selection's own team certificate signed it.
func verifyLogKeyRecordForSelection(sel *awconfig.Selection, rec *awid.LogKeyRecord) error {
	cert, err := loadTeamCertificateAt(sel.WorkingDir, sel.IdentityHome, sel.TeamID)
	if err != nil {
		return fmt.Errorf("load the team certificate to verify the log key: %w", err)
	}
	if err := awid.VerifyLogKeyRecord(rec, sel.TeamID, cert.TeamDIDKey); err != nil {
		return fmt.Errorf("log key for team %s: %w", sel.TeamID, err)
	}
	return nil
}

// appendLocalLogLine appends entry, one JSON object, to path: sealed to the
// owner log key when key holds one, plaintext when the team has none. Before
// the first sealed line, plaintext lines already in the file are sealed in
// place. tagOf, when set, names the visible tag each sealed line carries.
func appendLocalLogLine(path string, key localLogKey, entry []byte, tagOf func([]byte) string) error {
	if key.err != nil {
		return fmt.Errorf("owner log key is unusable, not logging: %w", key.err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := awconfig.LockExclusive(path + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()

	line := entry
	if key.record != nil {
		if err := sealPlaintextLogLines(path, key.record, tagOf); err != nil {
			return err
		}
		if line, err = sealLocalLogLine(key.record, entry, tagOf); err != nil {
			return err
		}
	}
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

// sealPlaintextLogLines rewrites path with every plaintext line sealed, in
// order, through a temporary file and a rename. The plaintext it replaces is
// not securely erased from the disk.
func sealPlaintextLogLines(path string, rec *awid.LogKeyRecord, tagOf func([]byte) string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var out bytes.Buffer
	changed := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if !isSealedLogLine(line) {
			if line, err = sealLocalLogLine(rec, line, tagOf); err != nil {
				return err
			}
			changed = true
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	if !changed {
		return nil
	}
	return atomicfile.Write(path, out.Bytes(), 0o600)
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
