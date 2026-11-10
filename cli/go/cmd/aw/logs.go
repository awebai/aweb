package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/logschain"
	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "A team's audit log",
}

var (
	logsVerifyBundle         string
	logsVerifyReceiptKeys    []string
	logsVerifyCheckpointKeys []string
	logsVerifyWitnesses      []string
)

var logsVerifyCmd = &cobra.Command{
	Use:   "verify --bundle FILE|- --receipt-key DID_KEY --checkpoint-key DID_KEY [--witness FILE]...",
	Short: "Verify an exported team log offline",
	Long: "Verify an exported team log (aweb.logs-export/1) offline, against the receipt and\n" +
		"checkpoint keys you accept and the receipts and checkpoints you hold yourself.\n\n" +
		"It reads only the files it is given: no workspace, identity or server.\n" +
		"Give each key you accept, for receipts and for checkpoints; a key that signs\n" +
		"both is given to both. Each --witness file holds one receipt or checkpoint per\n" +
		"line, in an export's own line shape. --bundle - reads the export from stdin.\n\n" +
		"Exits 0 when the bundle is intact, 1 when it is verified and not intact, and 2\n" +
		"when it could not be verified.",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return logsVerifyError("usage", "aw logs verify takes no arguments: %q", args[0])
		}
		return nil
	},
	RunE: runLogsVerify,
}

func init() {
	logsVerifyCmd.Flags().StringVar(&logsVerifyBundle, "bundle", "", "The export to verify, or - for stdin")
	logsVerifyCmd.Flags().StringArrayVar(&logsVerifyReceiptKeys, "receipt-key", nil, "A did:key you accept for receipts (repeatable)")
	logsVerifyCmd.Flags().StringArrayVar(&logsVerifyCheckpointKeys, "checkpoint-key", nil, "A did:key you accept for checkpoints (repeatable)")
	logsVerifyCmd.Flags().StringArrayVar(&logsVerifyWitnesses, "witness", nil, "A file of receipts and checkpoints you hold (repeatable)")
	logsVerifyCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		// Parsing stopped before --json could be read; the refusal still
		// answers in the form asked for.
		jsonFlag = jsonFlag || argsContainJSONFlag(os.Args[1:])
		return logsVerifyError("usage", "%v", err)
	})
	logsCmd.AddCommand(logsVerifyCmd)
	logsCmd.GroupID = groupUtility
	rootCmd.AddCommand(logsCmd)
	identityHomeNeutralCommandExemptions[logsVerifyCmd] = struct{}{}
	offlineCommands[logsVerifyCmd] = struct{}{}
}

// logsVerifyError is a verify that could not run: exit 2, with a stable code.
func logsVerifyError(code, format string, args ...any) error {
	return withErrorCode(code, &cliError{code: 2, msg: fmt.Sprintf(format, args...)})
}

func runLogsVerify(cmd *cobra.Command, _ []string) error {
	if logsVerifyBundle == "" {
		return logsVerifyError("usage", "--bundle is required")
	}
	receiptKeys, err := logsVerifyKeySet("--receipt-key", logsVerifyReceiptKeys)
	if err != nil {
		return err
	}
	checkpointKeys, err := logsVerifyKeySet("--checkpoint-key", logsVerifyCheckpointKeys)
	if err != nil {
		return err
	}
	var witnesses logschain.Witnesses
	for _, path := range logsVerifyWitnesses {
		if err := readLogsWitnessFile(&witnesses, path); err != nil {
			return err
		}
	}
	bundle := cmd.InOrStdin()
	if logsVerifyBundle != "-" {
		file, err := os.Open(logsVerifyBundle)
		if err != nil {
			return logsVerifyError("input_unreadable", "bundle: %v", err)
		}
		defer file.Close()
		bundle = file
	}
	report, err := logschain.VerifyBundle(bundle, receiptKeys, checkpointKeys, witnesses.Receipts, witnesses.Checkpoints)
	var malformed *logschain.BundleMalformed
	if errors.As(err, &malformed) {
		return logsVerifyError("bundle_malformed", "bundle %v", err)
	}
	if err != nil {
		return logsVerifyError("input_unreadable", "bundle: %v", err)
	}
	if jsonFlag {
		data, err := json.MarshalIndent(report.JSON(), "", "  ")
		if err != nil {
			return logsVerifyError("verify_failed", "report: %v", err)
		}
		fmt.Fprintln(commandStdout, string(data))
	} else {
		fmt.Fprint(commandStdout, logsVerifySummary(report))
	}
	if !report.Intact() {
		return &cliError{code: 1, msg: "the bundle is not intact"}
	}
	return nil
}

// logsVerifyKeySet is the keys given for one purpose: at least one, each an
// Ed25519 did:key. The bundle never supplies them.
func logsVerifyKeySet(flag string, keys []string) (map[string]bool, error) {
	if len(keys) == 0 {
		return nil, logsVerifyError("keys_invalid", "give at least one %s; a key that signs both receipts and checkpoints is given to both", flag)
	}
	set := map[string]bool{}
	for _, key := range keys {
		if _, err := awid.ExtractPublicKey(key); err != nil {
			return nil, logsVerifyError("keys_invalid", "%s %q is not an Ed25519 did:key", flag, key)
		}
		set[key] = true
	}
	return set, nil
}

func readLogsWitnessFile(witnesses *logschain.Witnesses, path string) error {
	if path == "-" {
		return logsVerifyError("usage", "--witness reads a file; only --bundle reads stdin")
	}
	file, err := os.Open(path)
	if err != nil {
		return logsVerifyError("input_unreadable", "witness: %v", err)
	}
	defer file.Close()
	err = witnesses.Read(file)
	var malformed *logschain.BundleMalformed
	if errors.As(err, &malformed) {
		return logsVerifyError("witness_malformed", "witness %s %v", path, err)
	}
	if err != nil {
		return logsVerifyError("input_unreadable", "witness %s: %v", path, err)
	}
	return nil
}

func logsVerifySummary(report logschain.BundleReport) string {
	var b strings.Builder
	if report.Intact() {
		b.WriteString("The bundle is intact.\n")
	} else {
		b.WriteString("The bundle is NOT intact.\n")
	}
	unanchored := false
	for _, epoch := range report.Epochs {
		state := "intact"
		if !epoch.Chain.Intact() {
			state = "not intact"
		}
		linked := "linked"
		if !epoch.Linked {
			linked = "NOT linked to the epoch before it"
		}
		fmt.Fprintf(&b, "Epoch %d: %s, %s.\n", epoch.ChainEpoch, state, linked)
		if epoch.Anchored {
			fmt.Fprintf(&b, "  Witnessed by a checkpoint up to team_seq %d.\n", epoch.AnchoredTo)
		} else {
			b.WriteString("  No checkpoint witnesses any of it.\n")
		}
		if epoch.Unanchored != nil {
			unanchored = true
			if epoch.Chain.Intact() {
				fmt.Fprintf(&b, "  Unanchored: team_seq %d-%d, present and verified, covered by no checkpoint.\n", epoch.Unanchored[0], epoch.Unanchored[1])
			} else {
				fmt.Fprintf(&b, "  Unanchored: team_seq %d-%d, present, covered by no checkpoint.\n", epoch.Unanchored[0], epoch.Unanchored[1])
			}
		}
		if br := epoch.Chain.FirstBreak; br != nil {
			fmt.Fprintf(&b, "  Breaks at team_seq %d: %s.\n", br.TeamSeq, br.Reason)
		}
		for _, gap := range epoch.Chain.Missing {
			fmt.Fprintf(&b, "  Missing: team_seq %d-%d.\n", gap[0], gap[1])
		}
		for _, purged := range epoch.Chain.Purged {
			fmt.Fprintf(&b, "  Purged: team_seq %d-%d, by %s.\n", purged.First, purged.Last, purged.Act)
		}
		for _, c := range epoch.Chain.Contradicted {
			fmt.Fprintf(&b, "  Contradicted %s %d of the epoch: %s.\n", c.Artefact, c.Index, c.Reason)
		}
	}
	if last := report.LastCheckpoint; last != nil {
		fmt.Fprintf(&b, "Last checkpoint: epoch %d, team_seq %d, signing bytes sha256 %s.\n", last.ChainEpoch, last.TeamSeq, last.SigningBytesSHA256)
	} else {
		b.WriteString("No checkpoint of the bundle holds.\n")
	}
	for _, c := range report.WitnessesContradicted {
		fmt.Fprintf(&b, "Your %s %d is contradicted: %s.\n", c.Artefact, c.Index, c.Reason)
	}
	b.WriteString("Limits: a bundle cannot prove it is complete. Events after its last checkpoint,\n" +
		"or whole trailing epochs, can be dropped and the rest still verifies; only a\n" +
		"receipt or checkpoint you hold yourself, given with --witness, proves the tail.\n" +
		"key_evidence proves only that its did_key signed the retained content, not that\n" +
		"this was the producer's declared key, nor its kid, purposes, installation,\n" +
		"generation or bindings.\n")
	if unanchored {
		b.WriteString("No checkpoint covers the unanchored ranges above.\n")
	}
	return b.String()
}
