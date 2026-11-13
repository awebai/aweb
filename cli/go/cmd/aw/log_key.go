package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/termtext"
)

// The owner's side of sealed local logs: creating a team's log key on the
// owner's machine, installing its signed public record on agent hosts, and
// reading sealed logs back with the private key from the owner's keychain.

// logKeyStore keeps owner log keys as encrypted backups by key id.
type logKeyStore interface {
	LoadLogKey(keyID string) ([]byte, error)
	SaveLogKey(keyID string, blob []byte) error
}

type logKeyCreateOptions struct {
	TeamID   string
	Keychain logKeyStore
	Prompt   awid.PassphrasePrompt
	Now      time.Time
}

// createLogKey makes a new owner log key for the team: the private key goes
// to the keychain under a new passphrase and the returned record is signed by
// the team controller key. Running it again rotates the key; earlier keys stay
// in the keychain so their lines remain readable.
func createLogKey(opts logKeyCreateOptions) (*awid.LogKeyRecord, error) {
	teamKey, err := loadOwnerTeamKey(opts.TeamID)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(teamKey)
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		return nil, err
	}
	rec, err := awid.NewLogKeyRecord(opts.TeamID, pair.Public, opts.Now)
	if err != nil {
		return nil, err
	}
	passphrase, err := opts.Prompt(fmt.Sprintf("Choose a passphrase for the log key of team %s (at least %d characters): ", rec.TeamID, awid.HumanKeyMinPassphrase))
	defer wipeBytes(passphrase)
	if err != nil {
		return nil, err
	}
	if len([]rune(string(passphrase))) < awid.HumanKeyMinPassphrase {
		return nil, fmt.Errorf("the passphrase must be at least %d characters; nothing was created", awid.HumanKeyMinPassphrase)
	}
	again, err := opts.Prompt("Type the passphrase again: ")
	defer wipeBytes(again)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(passphrase, again) {
		return nil, errors.New("the passphrases do not match; nothing was created")
	}
	blob, err := awid.ExportLogKeyBackup(pair.Private, passphrase)
	if err != nil {
		return nil, err
	}
	if err := opts.Keychain.SaveLogKey(rec.KeyID, blob); err != nil {
		return nil, err
	}
	if err := awid.SignLogKeyRecord(rec, teamKey); err != nil {
		return nil, err
	}
	return rec, nil
}

// installLogKeyRecord installs rec on this agent host once it verifies under
// the team key of the selection's own team certificate.
func installLogKeyRecord(sel *awconfig.Selection, rec *awid.LogKeyRecord) error {
	if sel == nil || strings.TrimSpace(sel.TeamID) == "" {
		return errors.New("no active team to install the log key for")
	}
	policyLock, err := awconfig.LockLogKeyPolicy(sel.TeamID)
	if err != nil {
		return err
	}
	defer policyLock.Close()
	if err := verifyLogKeyRecordForSelection(sel, rec); err != nil {
		return err
	}
	return awconfig.SaveLogKeyRecord(rec)
}

type logReadOptions struct {
	Files    []string
	Keychain logKeyStore
	Prompt   awid.PassphrasePrompt
	JSON     bool
	Out      io.Writer
}

// readOwnerLogs prints every line of the given logs, opening sealed lines
// with the owner's keys. Each key's passphrase is asked once.
func readOwnerLogs(opts logReadOptions) error {
	keys := map[string]*ecdh.PrivateKey{}
	for _, path := range opts.Files {
		lines, err := readLocalLogLines(path, 0)
		if err != nil {
			return err
		}
		for _, line := range lines {
			plaintext := line
			if sealed := sealedLogLineOf(line); sealed != nil {
				priv, err := ownerLogKey(keys, sealed.KeyID, opts)
				if err != nil {
					return err
				}
				if plaintext, err = awid.OpenLogLine(sealed, priv); err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
			}
			if err := printOwnerLogLine(opts.Out, plaintext, opts.JSON); err != nil {
				return err
			}
		}
	}
	return nil
}

func ownerLogKey(keys map[string]*ecdh.PrivateKey, keyID string, opts logReadOptions) (*ecdh.PrivateKey, error) {
	if priv, ok := keys[keyID]; ok {
		return priv, nil
	}
	blob, err := opts.Keychain.LoadLogKey(keyID)
	if errors.Is(err, awconfig.ErrLogKeyNotFound) {
		return nil, fmt.Errorf("log key %s is not in this machine's keychain; read the log where that key was created", keyID)
	}
	if err != nil {
		return nil, err
	}
	passphrase, err := opts.Prompt(fmt.Sprintf("Passphrase for log key %s: ", keyID))
	defer wipeBytes(passphrase)
	if err != nil {
		return nil, err
	}
	priv, err := awid.ImportLogKeyBackup(blob, passphrase)
	if err != nil {
		return nil, fmt.Errorf("open log key %s: %w", keyID, err)
	}
	keys[keyID] = priv
	return priv, nil
}

// printOwnerLogLine prints one entry of either local log: an interaction
// entry carries a kind, a communication-log entry does not. Whoever can write
// a log can seal lines to the owner's public key, so every entry is untrusted
// and is printed with terminal control escaped: as text through termtext, or
// under --json as JSON whose unsafe runes are \u escapes. A line that is not
// a JSON object is printed as text, or under --json as {"raw": <line>}.
func printOwnerLogLine(out io.Writer, plaintext []byte, asJSON bool) error {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(plaintext, &probe); err != nil {
		if asJSON {
			raw, err := json.Marshal(map[string]string{"raw": string(plaintext)})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(out, string(termtext.JSON(raw)))
			return err
		}
		_, err := fmt.Fprintln(out, termtext.Line(string(plaintext)))
		return err
	}
	if asJSON {
		var compact bytes.Buffer
		if err := json.Compact(&compact, plaintext); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, string(termtext.JSON(compact.Bytes())))
		return err
	}
	if probe.Kind != "" {
		var entry InteractionEntry
		if err := json.Unmarshal(plaintext, &entry); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, termtext.Line(fmt.Sprintf("[%s] %s", formatLogTimestamp(entry.Timestamp), formatInteractionEntry(entry))))
		return err
	}
	var entry CommLogEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return err
	}
	_, err := fmt.Fprint(out, formatLogLine(&entry))
	return err
}

var logKeyCreateOut string

var teamLogKeyCmd = &cobra.Command{
	Use:   "log-key",
	Short: "Manage the owner key that agents' local message logs are sealed to",
}

var teamLogKeyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create (or rotate) the team's owner log key; prints its signed public record",
	Long: "Create a new log key for the team on the owner's machine. The private key is kept in\n" +
		"the OS keychain under a passphrase; the public record, signed with the team controller\n" +
		"key, is written to --out (or stdout) for `aw team admin log-key install` on each agent host.\n" +
		"Running it again rotates the key; earlier keys stay in the keychain.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		teamID := strings.TrimSpace(teamFlag)
		if teamID == "" {
			_, sel, err := resolveClientSelection()
			if err != nil {
				return err
			}
			teamID = sel.TeamID
		}
		rec, err := createLogKey(logKeyCreateOptions{
			TeamID:   teamID,
			Keychain: awconfig.LogKeychain{},
			Prompt:   awid.TerminalPassphrasePrompt(),
			Now:      time.Now(),
		})
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if strings.TrimSpace(logKeyCreateOut) == "" {
			_, err = cmd.OutOrStdout().Write(data)
			return err
		}
		if err := os.WriteFile(logKeyCreateOut, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Log key %s for team %s written to %s\n", rec.KeyID, rec.TeamID, logKeyCreateOut)
		return nil
	},
}

var teamLogKeyInstallCmd = &cobra.Command{
	Use:   "install <record-file>",
	Short: "Install the team's owner log key record on this host; local logs are then sealed to it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var rec awid.LogKeyRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("parse log key record %s: %w", args[0], err)
		}
		_, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := installLogKeyRecord(sel, &rec); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Installed log key %s for team %s; local mail and chat logs are now sealed to it.\n", rec.KeyID, rec.TeamID)
		return nil
	},
}

var logReadCmd = &cobra.Command{
	Use:   "read <log-file>...",
	Short: "Read sealed local logs with the owner's log keys from this machine's keychain",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return readOwnerLogs(logReadOptions{
			Files:    args,
			Keychain: awconfig.LogKeychain{},
			Prompt:   awid.TerminalPassphrasePrompt(),
			JSON:     jsonFlag,
			Out:      cmd.OutOrStdout(),
		})
	},
}

func init() {
	teamLogKeyCreateCmd.Flags().StringVar(&logKeyCreateOut, "out", "", "Write the signed public record to this file instead of stdout")
	teamLogKeyCmd.AddCommand(teamLogKeyCreateCmd, teamLogKeyInstallCmd)
	bindTeamSelector(teamLogKeyCmd)
	teamLogKeyCmd.GroupID = teamAdminGroupOperations
	teamAdminCmd.AddCommand(teamLogKeyCmd)
	logCmd.AddCommand(logReadCmd)
}
