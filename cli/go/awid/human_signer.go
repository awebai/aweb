package awid

// The human signer of option C: the human key lives in the OS keychain only
// as its encrypted backup (the frozen PBES2 export), and each signature asks
// for the passphrase on the terminal. The decrypted key exists for that one
// signature and is wiped.
import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

var (
	// ErrHumanKeyNotFound means no human key is installed for the identity.
	ErrHumanKeyNotFound = errors.New("no human key installed")
	// ErrNoTerminal means no terminal can be asked for the passphrase. There
	// is no fallback to arguments, environment or files.
	ErrNoTerminal = errors.New("a human signature needs a passphrase typed on a terminal")
)

// HumanKeyStore holds encrypted human key backups by identity.
type HumanKeyStore interface {
	LoadHumanKey(id string) ([]byte, error)
	SaveHumanKey(id string, blob []byte) error
}

// PassphrasePrompt asks the human for a passphrase. The caller wipes it.
type PassphrasePrompt func(prompt string) ([]byte, error)

// HumanKeyMinPassphrase is the shortest passphrase accepted when a human key
// is installed. An imported backup keeps the passphrase it was made with.
const HumanKeyMinPassphrase = 12

// InstallHumanKey stores key for id as its encrypted backup.
func InstallHumanKey(store HumanKeyStore, id string, key ed25519.PrivateKey, passphrase []byte) error {
	if len(passphrase) > 0 && len([]rune(string(passphrase))) < HumanKeyMinPassphrase {
		return humanKeyBackupRefusal("passphrase_too_short")
	}
	blob, err := ExportHumanKeyBackup(key, passphrase)
	if err != nil {
		return err
	}
	return store.SaveHumanKey(id, blob)
}

// HumanSigner signs as the human id, asking for the passphrase each time.
// description names the operation, subject and target, and is shown in the
// prompt.
func HumanSigner(store HumanKeyStore, id, description string, prompt PassphrasePrompt) IDCertificateSigner {
	return func(payload []byte) (string, []byte, error) {
		blob, err := store.LoadHumanKey(id)
		if err != nil {
			return "", nil, err
		}
		passphrase, err := prompt(fmt.Sprintf("Sign as %s to %s.\nPassphrase for that human key: ", id, description))
		defer wipe(passphrase)
		if err != nil {
			return "", nil, err
		}
		key, err := ImportHumanKeyBackup(blob, passphrase)
		if err != nil {
			return "", nil, err
		}
		defer wipe(key)
		return ComputeDIDKey(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, payload), nil
	}
}

// TerminalPassphrasePrompt reads a passphrase from the controlling terminal
// without echo.
func TerminalPassphrasePrompt() PassphrasePrompt {
	return func(prompt string) ([]byte, error) {
		return terminalPassphrase(controllingTerminalInput, controllingTerminalOutput, prompt)
	}
}

func terminalPassphrase(inputPath, outputPath, prompt string) ([]byte, error) {
	input, err := os.OpenFile(inputPath, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer input.Close()
	if !term.IsTerminal(int(input.Fd())) {
		return nil, ErrNoTerminal
	}
	output, err := os.OpenFile(outputPath, os.O_WRONLY, 0)
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer output.Close()
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return nil, err
	}
	passphrase, err := term.ReadPassword(int(input.Fd()))
	_, _ = fmt.Fprintln(output)
	return passphrase, err
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
