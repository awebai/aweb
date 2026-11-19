package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/awebai/aw/internal/handoff"
	"github.com/awebai/aw/internal/termtext"
	"github.com/spf13/cobra"
)

// printActionResponse writes the members terminal_output names only to the
// controlling terminal and prints the rest. The terminal-output rule in
// docs/design/human-confirmation-from-aw.md keeps protected values off stdout;
// termtext owns escaping for every displayed server-controlled value.
func printActionResponse(cmd *cobra.Command, resp *handoff.Response, terminalOutput []string) error {
	var body any
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		if len(terminalOutput) > 0 {
			return fmt.Errorf("the app's answer is not JSON, so its terminal-only members cannot be separated")
		}
		_, err := io.WriteString(cmd.OutOrStdout(), termtext.Body(string(resp.Body)))
		return err
	}
	if len(terminalOutput) > 0 {
		taken, rest := takeTerminalOutput(body, terminalOutput)
		if err := writeToTerminal(taken); err != nil {
			return err
		}
		body = rest
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, termtext.JSON(data), "", "  "); err != nil {
		return fmt.Errorf("format the app response: %w", err)
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), formatted.String())
	return err
}

// writeToTerminal writes each value to the controlling terminal, labelled
// with its pointer. It is never logged or traced.
func writeToTerminal(values []terminalValue) (result error) {
	if len(values) == 0 {
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return withErrorCode("protected_output_unavailable", fmt.Errorf("open the controlling terminal: %w", err))
	}
	defer func() { result = errors.Join(result, tty.Close()) }()
	return writeTerminalValues(tty, values)
}

func writeTerminalValues(output io.Writer, values []terminalValue) error {
	for _, v := range values {
		text, ok := v.Value.(string)
		if !ok {
			data, err := json.Marshal(v.Value)
			if err != nil {
				return fmt.Errorf("encode protected output %s: %w", termtext.Line(v.Pointer), err)
			}
			text = string(data)
		}
		if _, err := io.WriteString(output, termtext.Line(v.Pointer)+": "+termtext.Line(text)+"\n"); err != nil {
			return err
		}
	}
	return nil
}
