package awid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
)

// memoryHumanKeys stands in for the OS keychain: it stores exactly the bytes
// it is given.
type memoryHumanKeys map[string][]byte

func (m memoryHumanKeys) LoadHumanKey(id string) ([]byte, error) {
	blob, ok := m[id]
	if !ok {
		return nil, ErrHumanKeyNotFound
	}
	return append([]byte(nil), blob...), nil
}

func (m memoryHumanKeys) SaveHumanKey(id string, blob []byte) error {
	m[id] = append([]byte(nil), blob...)
	return nil
}

const testHumanID = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"

func testHumanKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
}

// scriptedPrompt answers each prompt with the next passphrase and keeps every
// slice it handed out, so a test can see that the signer wiped it.
type scriptedPrompt struct {
	answers [][]byte
	given   [][]byte
	texts   []string
}

func (p *scriptedPrompt) prompt(text string) ([]byte, error) {
	p.texts = append(p.texts, text)
	if len(p.answers) == 0 {
		return nil, errors.New("no passphrase scripted")
	}
	answer := p.answers[0]
	p.answers = p.answers[1:]
	p.given = append(p.given, answer)
	return answer, nil
}

func installedHumanKey(t *testing.T) memoryHumanKeys {
	t.Helper()
	store := memoryHumanKeys{}
	if err := InstallHumanKey(store, testHumanID, testHumanKey(), []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestHumanKeyIsStoredOnlyAsTheEncryptedBackup(t *testing.T) {
	store := installedHumanKey(t)
	blob := store[testHumanID]
	block, _ := pem.Decode(blob)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatal("the stored item is not an encrypted PKCS#8 backup")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		t.Fatal("the stored item parses as a plaintext private key")
	}
	key := testHumanKey()
	if bytes.Contains(blob, key.Seed()) || bytes.Contains(block.Bytes, key.Seed()) {
		t.Fatal("the stored item contains the private key")
	}
	if _, err := ImportHumanKeyBackup(blob, []byte("correct horse")); err != nil {
		t.Fatalf("the stored item is not the frozen backup format: %v", err)
	}
}

func TestInstallHumanKeyRefusesAnEmptyPassphrase(t *testing.T) {
	store := memoryHumanKeys{}
	if err := InstallHumanKey(store, testHumanID, testHumanKey(), nil); HumanKeyBackupErrorCode(err) != "passphrase_required" || len(store) != 0 {
		t.Fatalf("err=%v stored=%d", err, len(store))
	}
}

func TestHumanSignerPromptsForEachSignatureAndWipesThePassphrase(t *testing.T) {
	store := installedHumanKey(t)
	prompt := &scriptedPrompt{answers: [][]byte{[]byte("correct horse"), []byte("correct horse")}}
	sign := HumanSigner(store, testHumanID, "approve human certificate for did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj in example.com", prompt.prompt)
	want := ComputeDIDKey(testHumanKey().Public().(ed25519.PublicKey))
	for i, payload := range [][]byte{[]byte("first"), []byte("second")} {
		didKey, signature, err := sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		if didKey != want || !ed25519.Verify(testHumanKey().Public().(ed25519.PublicKey), payload, signature) {
			t.Fatalf("signature %d does not verify under the human key", i)
		}
		if len(prompt.given) != i+1 {
			t.Fatalf("signature %d used %d prompts", i, len(prompt.given))
		}
	}
	for _, text := range prompt.texts {
		if !strings.Contains(text, "approve human certificate for did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj in example.com") || !strings.Contains(text, testHumanID) {
			t.Fatalf("the prompt does not say what is signed: %q", text)
		}
	}
	for i, passphrase := range prompt.given {
		if !bytes.Equal(passphrase, make([]byte, len(passphrase))) {
			t.Fatalf("passphrase %d was not wiped", i)
		}
	}
}

func TestHumanSignerRefusesWithoutSigning(t *testing.T) {
	for name, tc := range map[string]struct {
		store      memoryHumanKeys
		passphrase []byte
		code       string
		err        error
	}{
		"wrong passphrase": {installedHumanKey(t), []byte("wrong"), "backup_decryption_failed", nil},
		"empty passphrase": {installedHumanKey(t), []byte{}, "passphrase_required", nil},
		"no installed key": {memoryHumanKeys{}, []byte("correct horse"), "", ErrHumanKeyNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			prompt := &scriptedPrompt{answers: [][]byte{tc.passphrase}}
			didKey, signature, err := HumanSigner(tc.store, testHumanID, "register", prompt.prompt)([]byte("payload"))
			if didKey != "" || signature != nil {
				t.Fatal("a refused signing returned a signature")
			}
			if tc.err != nil && !errors.Is(err, tc.err) || tc.code != "" && HumanKeyBackupErrorCode(err) != tc.code {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestHumanSignerRefusesWhenThePromptFails(t *testing.T) {
	store := installedHumanKey(t)
	headless := func(string) ([]byte, error) { return nil, ErrNoTerminal }
	if _, _, err := HumanSigner(store, testHumanID, "register", headless)([]byte("payload")); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("err=%v", err)
	}
}

func TestTerminalPromptRefusesWithoutATerminal(t *testing.T) {
	regular := t.TempDir() + "/not-a-tty"
	if err := os.WriteFile(regular, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"no terminal device": t.TempDir() + "/missing-tty", "a regular file": regular} {
		t.Run(name, func(t *testing.T) {
			passphrase, err := terminalPassphrase(path, path, "passphrase: ")
			if !errors.Is(err, ErrNoTerminal) || passphrase != nil {
				t.Fatalf("passphrase=%q err=%v", passphrase, err)
			}
		})
	}
}

func TestInstallHumanKeyRequiresTwelveCharacters(t *testing.T) {
	store := memoryHumanKeys{}
	if err := InstallHumanKey(store, testHumanID, testHumanKey(), []byte("elevenchars")); HumanKeyBackupErrorCode(err) != "passphrase_too_short" || len(store) != 0 {
		t.Fatalf("err=%v stored=%d", err, len(store))
	}
	if err := InstallHumanKey(store, testHumanID, testHumanKey(), []byte("twelve chars")); err != nil {
		t.Fatal(err)
	}
}

func TestValidateHumanKeyBackupIsStructural(t *testing.T) {
	store := installedHumanKey(t)
	good := store[testHumanID]
	if err := ValidateHumanKeyBackup(good); err != nil {
		t.Fatalf("a real backup was refused: %v", err)
	}
	if err := ValidateHumanKeyBackup(append(append([]byte(nil), good...), "\n  \n"...)); err != nil {
		t.Fatalf("trailing whitespace was refused: %v", err)
	}
	plaintextDER, err := x509.MarshalPKCS8PrivateKey(testHumanKey())
	if err != nil {
		t.Fatal(err)
	}
	plaintextPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plaintextDER})
	for name, blob := range map[string][]byte{
		"plaintext PEM appended":                  append(append([]byte(nil), good...), plaintextPEM...),
		"plaintext DER under the ENCRYPTED label": pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: plaintextDER}),
		"plaintext PEM":                           plaintextPEM,
		"text after the block":                    append(append([]byte(nil), good...), "note"...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHumanKeyBackup(blob); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
