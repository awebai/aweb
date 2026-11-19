package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// printActionResponse writes the members terminal_output names only to the
// controlling terminal and prints the rest.
func printActionResponse(cmd *cobra.Command, resp *handoff.Response, terminalOutput []string) error {
	var body any
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		if len(terminalOutput) > 0 {
			return fmt.Errorf("the app's answer is not JSON, so its terminal-only members cannot be separated")
		}
		_, err := cmd.OutOrStdout().Write(resp.Body)
		return err
	}
	if len(terminalOutput) > 0 {
		taken, rest := takeTerminalOutput(body, terminalOutput)
		if err := writeToTerminal(taken); err != nil {
			return err
		}
		body = rest
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return err
}

// writeToTerminal writes each value to the controlling terminal, labelled
// with its pointer. It is never logged or traced.
func writeToTerminal(values []terminalValue) error {
	if len(values) == 0 {
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return withErrorCode("protected_output_unavailable", fmt.Errorf("open the controlling terminal: %w", err))
	}
	defer tty.Close()
	for _, v := range values {
		text, ok := v.Value.(string)
		if !ok {
			data, _ := json.Marshal(v.Value)
			text = string(data)
		}
		if _, err := io.WriteString(tty, v.Pointer+": "+text+"\n"); err != nil {
			return err
		}
	}
	return nil
}
