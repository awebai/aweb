package awid

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/creack/pty"
)

func TestTerminalConfirmIsYesOnlyForAnExplicitYes(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "Yes\n": true, " YES \n": true, "\n": false, "n\n": false, "yes please\n": false, "maybe\n": false} {
		master, tty, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = io.Copy(io.Discard, master) }()
		if _, err := master.Write([]byte(answer)); err != nil {
			t.Fatal(err)
		}
		got, err := terminalConfirm(tty.Name(), tty.Name(), "Does it match? [y/N] ")
		_ = tty.Close()
		_ = master.Close()
		if err != nil || got != want {
			t.Fatalf("%q: got %v (%v) want %v", strings.TrimSpace(answer), got, err, want)
		}
	}
}

func TestTerminalConfirmRefusesWithoutATerminal(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("y\n")
	_ = file.Close()
	if ok, err := terminalConfirm(file.Name(), file.Name(), "Does it match? [y/N] "); err != ErrNoTerminal || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestTerminalTextUsesTheControllingTerminal(t *testing.T) {
	master, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer tty.Close()
	go func() { _, _ = io.Copy(io.Discard, master) }()
	if _, err = master.Write([]byte("2\n")); err != nil {
		t.Fatal(err)
	}
	got, err := terminalText(tty.Name(), tty.Name(), "How many keys? ")
	if err != nil || got != "2" {
		t.Fatalf("%q %v", got, err)
	}
	file := t.TempDir() + "/pipe-input"
	if err = os.WriteFile(file, []byte("2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := terminalText(file, file, "How many keys? "); err != ErrNoTerminal {
		t.Fatalf("read redirected input: %v", err)
	}
}
