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

// createLogKey makes a new owner log key for the team on the machine where
// the owner reads the logs: the private key goes to the keychain under a new
// passphrase, and the returned record is unsigned. It needs no controller key;
// signLogKey signs the record wherever the controller key is held. Running it
// again rotates the key; earlier keys stay in the keychain so their lines
// remain readable.
func createLogKey(opts logKeyCreateOptions) (*awid.LogKeyRecord, error) {
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
	return rec, nil
}

type logKeySignOptions struct {
	Record *awid.LogKeyRecord
	// OfflineControllerKey signs with the team controller key in this
	// machine's ~/.awid/team-keys/: an explicit route outside a deployment
	// whose controller key lives only in its signer.
	OfflineControllerKey bool
	// TeamKeyDID and Signature attach a signature produced elsewhere.
	TeamKeyDID string
	Signature  string
}

// signLogKey completes opts.Record through exactly one route, chosen by the
// caller: the explicit offline controller key, or a signature produced
// elsewhere and verified before it is attached. With no route, or both, it
// refuses rather than choose one. A refused sign leaves the record as it was.
// Signing an already signed record replaces its signature, as after a
// controller replacement.
func signLogKey(opts logKeySignOptions) error {
	if opts.Record == nil {
		return errors.New("missing log key record")
	}
	attach := strings.TrimSpace(opts.TeamKeyDID) != "" || strings.TrimSpace(opts.Signature) != ""
	switch {
	case opts.OfflineControllerKey && attach:
		return usageError("choose one route: --offline-controller-key, or --team-key-did with --signature")
	case opts.OfflineControllerKey:
		teamKey, err := loadOwnerTeamKey(opts.Record.TeamID)
		if err != nil {
			return err
		}
		defer wipeBytes(teamKey)
		return awid.SignLogKeyRecord(opts.Record, teamKey)
	case attach:
		if strings.TrimSpace(opts.TeamKeyDID) == "" || strings.TrimSpace(opts.Signature) == "" {
			return usageError("attaching a signature needs both --team-key-did and --signature")
		}
		return awid.AttachLogKeyRecordSignature(opts.Record, opts.TeamKeyDID, opts.Signature)
	default:
		return usageError("say how the record is signed: --team-key-did with --signature to attach a signature produced elsewhere, or --offline-controller-key to sign with the controller key in ~/.awid/team-keys/ (outside a deployment whose signer holds it)")
	}
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

var (
	logKeyCreateOut      string
	logKeySignRecord     string
	logKeySignOut        string
	logKeySignOffline    bool
	logKeySignTeamKeyDID string
	logKeySignSignature  string
)

var teamLogKeyCmd = &cobra.Command{
	Use:   "log-key",
	Short: "Manage the owner key that agents' local message logs are sealed to",
}

var teamLogKeyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create (or rotate) the team's owner log key; prints its unsigned public record",
	Long: "Create a new log key for the team on the machine where the owner reads the logs. The\n" +
		"private key is kept in the OS keychain under a passphrase. The public record is written\n" +
		"to --out (or stdout) unsigned: sign it with `aw team admin log-key sign` wherever the\n" +
		"team controller key is held, then install it with `aw team admin log-key install` on\n" +
		"each agent host. Running it again rotates the key; earlier keys stay in the keychain.",
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
		return writeLogKeyRecord(cmd, rec, logKeyCreateOut, "Unsigned log key record %s for team %s written to %s; sign it with `aw team admin log-key sign`.\n")
	},
}

var teamLogKeySignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a log key record, or attach a signature made elsewhere",
	Long: "Complete a log key record through exactly one route:\n" +
		"  --team-key-did and --signature attach a signature produced elsewhere, such as by the\n" +
		"  deployment's protected signer, after verifying it over the record's signing bytes;\n" +
		"  --offline-controller-key signs with the team controller key in ~/.awid/team-keys/ on\n" +
		"  this machine, which is outside the route of a deployment whose signer holds that key.\n" +
		"With no route, or both, it refuses. The signed record is written to --out (or stdout).",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rec, err := readLogKeyRecordFile(logKeySignRecord)
		if err != nil {
			return err
		}
		if err := signLogKey(logKeySignOptions{
			Record:               rec,
			OfflineControllerKey: logKeySignOffline,
			TeamKeyDID:           logKeySignTeamKeyDID,
			Signature:            logKeySignSignature,
		}); err != nil {
			return err
		}
		return writeLogKeyRecord(cmd, rec, logKeySignOut, "Log key record %s for team %s signed and written to %s; install it with `aw team admin log-key install`.\n")
	},
}

var teamLogKeySigningBytesCmd = &cobra.Command{
	Use:   "signing-bytes",
	Short: "Print the exact bytes a team key signs for a log key record",
	Long: "Print, with no trailing newline, the bytes the team controller key --team-key-did signs\n" +
		"for the record: the aweb.log-key/1 prefix and the canonical JSON of its unsigned fields.\n" +
		"Use it to cross-check what any signer is asked to sign.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rec, err := readLogKeyRecordFile(logKeySignRecord)
		if err != nil {
			return err
		}
		rec.TeamKeyDID = strings.TrimSpace(logKeySignTeamKeyDID)
		signing, err := awid.LogKeyRecordSigningBytes(rec)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(signing)
		return err
	},
}

func readLogKeyRecordFile(path string) (*awid.LogKeyRecord, error) {
	if strings.TrimSpace(path) == "" {
		return nil, usageError("--record is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec awid.LogKeyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse log key record %s: %w", path, err)
	}
	return &rec, nil
}

// writeLogKeyRecord writes the public record to out, or to stdout when out
// is empty; done names the written file on stderr.
func writeLogKeyRecord(cmd *cobra.Command, rec *awid.LogKeyRecord, out, done string) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if strings.TrimSpace(out) == "" {
		_, err = cmd.OutOrStdout().Write(data)
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), done, rec.KeyID, rec.TeamID, out)
	return nil
}

var teamLogKeyInstallCmd = &cobra.Command{
	Use:   "install <record-file>",
	Short: "Install the team's owner log key record on this host; local logs are then sealed to it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rec, err := readLogKeyRecordFile(args[0])
		if err != nil {
			return err
		}
		_, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := installLogKeyRecord(sel, rec); err != nil {
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
	teamLogKeyCreateCmd.Flags().StringVar(&logKeyCreateOut, "out", "", "Write the unsigned public record to this file instead of stdout")
	teamLogKeySignCmd.Flags().StringVar(&logKeySignRecord, "record", "", "The log key record to sign")
	teamLogKeySignCmd.Flags().StringVar(&logKeySignOut, "out", "", "Write the signed record to this file instead of stdout")
	teamLogKeySignCmd.Flags().BoolVar(&logKeySignOffline, "offline-controller-key", false, "Sign with the team controller key in ~/.awid/team-keys/ on this machine")
	teamLogKeySignCmd.Flags().StringVar(&logKeySignTeamKeyDID, "team-key-did", "", "The did:key of the team key that produced --signature")
	teamLogKeySignCmd.Flags().StringVar(&logKeySignSignature, "signature", "", "A signature produced elsewhere: unpadded standard base64 of the 64 Ed25519 bytes")
	teamLogKeySigningBytesCmd.Flags().StringVar(&logKeySignRecord, "record", "", "The log key record")
	teamLogKeySigningBytesCmd.Flags().StringVar(&logKeySignTeamKeyDID, "team-key-did", "", "The did:key of the team key that will sign")
	teamLogKeyCmd.AddCommand(teamLogKeyCreateCmd, teamLogKeySignCmd, teamLogKeySigningBytesCmd, teamLogKeyInstallCmd)
	bindTeamSelector(teamLogKeyCmd)
	teamLogKeyCmd.GroupID = teamAdminGroupOperations
	teamAdminCmd.AddCommand(teamLogKeyCmd)
	logCmd.AddCommand(logReadCmd)
}
