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
