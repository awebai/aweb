package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
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

		entries, err := readCommLog(path, logLimit)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No log entries yet.")
				return nil
			}
			return err
		}

		entries = filterCommLog(entries, logChannel, logFrom)

		if jsonFlag {
			for _, e := range entries {
				data, _ := json.Marshal(e)
				fmt.Println(string(data))
			}
			return nil
		}

		if len(entries) == 0 {
			fmt.Println("No matching log entries.")
			return nil
		}

		for _, e := range entries {
			fmt.Print(formatLogLine(&e))
		}
		return nil
	},
}

// readCommLog reads JSONL entries from a log file.
// If limit > 0, returns only the last `limit` entries.
func readCommLog(path string, limit int) ([]CommLogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []CommLogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e CommLogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
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

// formatLogLine formats one log entry for human display.
func formatLogLine(e *CommLogEntry) string {
	ts := e.Timestamp
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		ts = t.Format("2006-01-02 15:04:05")
	}

	arrow := "←"
	peer := e.From
	if e.Dir == "send" {
		arrow = "→"
		peer = e.To
	}

	// Chat is the most common channel; only tag mail/dm to reduce noise.
	chTag := ""
	if e.Channel != "" && e.Channel != "chat" {
		chTag = " (" + e.Channel + ")"
	}

	subj := ""
	if e.Subject != "" {
		subj = e.Subject + " — "
	}

	return fmt.Sprintf("[%s] %s %s%s: %s%s\n", ts, arrow, peer, chTag, subj, e.Body)
}

func init() {
	logCmd.Flags().IntVar(&logLimit, "limit", 20, "Max entries to show")
	logCmd.Flags().StringVar(&logChannel, "channel", "", "Filter by channel (mail, chat, dm)")
	logCmd.Flags().StringVar(&logFrom, "from", "", "Filter by sender (substring match)")

	rootCmd.AddCommand(logCmd)
}
