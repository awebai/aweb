package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/awebai/aw/internal/termtext"
)

var (
	logLimit   int
	logChannel string
	logFrom    string
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Show local communication log",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		path := commLogPath(logsDir, commLogNameForSelection(sel))
		if localLogPolicyForSelection(sel).sealing() {
			return withErrorCode("local_log_sealed", fmt.Errorf("the local log of team %s is sealed to the team's owner log key; the owner reads it with `aw log read %s` on the machine that holds that key", sel.TeamID, path))
		}

		entries, err := readCommLog(path, logLimit)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintln(commandStdout, "No log entries yet.")
				return nil
			}
			return err
		}

		entries = filterCommLog(entries, logChannel, logFrom)

		if jsonFlag {
			for _, e := range entries {
				data, _ := json.Marshal(e)
				fmt.Fprintln(commandStdout, string(data))
			}
			return nil
		}

		if len(entries) == 0 {
			fmt.Fprintln(commandStdout, "No matching log entries.")
			return nil
		}

		for _, e := range entries {
			fmt.Fprint(commandStdout, formatLogLine(&e))
		}
		return nil
	},
}

// readCommLog reads the plaintext JSONL entries of a log file; sealed lines
// are for the owner and are skipped.
// If limit > 0, returns only the last `limit` entries.
func readCommLog(path string, limit int) ([]CommLogEntry, error) {
	lines, err := readLocalLogLines(path, 0)
	if err != nil {
		return nil, err
	}

	var entries []CommLogEntry
	for _, line := range lines {
		if isSealedLogLine(line) {
			continue
		}
		var e CommLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, nil
}

// filterCommLog filters entries by channel and/or from (substring match).
func filterCommLog(entries []CommLogEntry, channel, from string) []CommLogEntry {
	if channel == "" && from == "" {
		return entries
	}
	var out []CommLogEntry
	for _, e := range entries {
		if channel != "" && e.Channel != channel {
			continue
		}
		if from != "" && !strings.Contains(e.From, from) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// formatLogTimestamp shows an RFC 3339 log timestamp as local-log text.
func formatLogTimestamp(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Format("2006-01-02 15:04:05")
	}
	return ts
}

// formatLogLine formats one log entry for human display.
func formatLogLine(e *CommLogEntry) string {
	ts := termtext.Line(formatLogTimestamp(e.Timestamp))

	arrow := "←"
	peer := e.From
	if e.Dir == "send" {
		arrow = "→"
		peer = e.To
	}

	// Chat is the most common channel; only tag mail/dm to reduce noise.
	chTag := ""
	if e.Channel != "" && e.Channel != "chat" {
		chTag = " (" + termtext.Line(e.Channel) + ")"
	}

	subj := ""
	if e.Subject != "" {
		subj = termtext.Line(e.Subject) + " — "
	}

	return fmt.Sprintf("[%s] %s %s%s: %s%s\n", ts, arrow, termtext.Line(peer), chTag, subj, termtext.Block(e.Body))
}

func init() {
	logCmd.Flags().IntVar(&logLimit, "limit", 20, "Max entries to show")
	logCmd.Flags().StringVar(&logChannel, "channel", "", "Filter by channel (mail, chat, dm)")
	logCmd.Flags().StringVar(&logFrom, "from", "", "Filter by sender (substring match)")

	rootCmd.AddCommand(logCmd)
}
