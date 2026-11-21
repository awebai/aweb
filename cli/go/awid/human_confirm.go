package awid

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ConfirmPrompt asks a human a yes/no question. Only an explicit yes is
// true; a blank answer, any other answer or a failed read is no.
type ConfirmPrompt func(question string) (bool, error)

// TerminalConfirmPrompt asks on the controlling terminal. Without one it
// refuses rather than reading an answer from anywhere else.
func TerminalConfirmPrompt() ConfirmPrompt {
	return func(question string) (bool, error) {
		return terminalConfirm(controllingTerminalInput, controllingTerminalOutput, question)
	}
}

func terminalConfirm(inputPath, outputPath, question string) (bool, error) {
	line, err := terminalText(inputPath, outputPath, question)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// TerminalTextPrompt reads a non-secret answer only from the controlling terminal.
// It never consumes piped command input.
func TerminalTextPrompt() func(string) (string, error) {
	return func(question string) (string, error) {
		return terminalText(controllingTerminalInput, controllingTerminalOutput, question)
	}
}

func terminalText(inputPath, outputPath, question string) (string, error) {
	input, err := os.OpenFile(inputPath, os.O_RDWR, 0)
	if err != nil {
		return "", ErrNoTerminal
	}
	defer input.Close()
	if !term.IsTerminal(int(input.Fd())) {
		return "", ErrNoTerminal
	}
	output, err := os.OpenFile(outputPath, os.O_WRONLY, 0)
	if err != nil {
		return "", ErrNoTerminal
	}
	defer output.Close()
	if _, err := fmt.Fprint(output, question); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
