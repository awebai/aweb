package awid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/crashtest"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/awebai/aw/signaturewire"
)

// GenerateKeypair creates a new Ed25519 keypair using crypto/rand.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// SaveKeypair writes a keypair to keysDir as PEM files named by agent address.
// Private key: 0600. Public key: 0644.
func SaveKeypair(keysDir, address string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	base := addressToKeyFileBase(address)
	keyPath := filepath.Join(keysDir, base+".signing.key")
	pubPath := filepath.Join(keysDir, base+".signing.pub")
	return SaveKeypairAt(keyPath, pubPath, pub, priv)
}

// SaveKeypairAt writes a keypair to explicit PEM file paths.
func SaveKeypairAt(keyPath, pubPath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if err := writePrivateKey(keyPath, priv); err != nil {
		return err
	}
	// Crash-test observation only; inert without the inherited pipe capability.
	crashtest.Checkpoint("after-keypair-private-commit", keyPath)
	if err := writePublicKey(pubPath, pub); err != nil {
		return err
	}
	crashtest.Checkpoint("after-keypair-public-commit", pubPath)
	return nil
}

// SaveSigningKey writes only the private signing key PEM to the given path.
func SaveSigningKey(path string, priv ed25519.PrivateKey) error {
	return StoreSigningKeyFile(SigningKeyFile{Path: path, Key: priv, PathPolicy: IdentityKeyPath})
}

type PrivateKeyPathPolicy uint8

const (
	IdentityKeyPath PrivateKeyPathPolicy = iota
	OperatorManagedAuthorityPath
)

type SigningKeyFile struct {
	Path       string
	Key        ed25519.PrivateKey
	PathPolicy PrivateKeyPathPolicy
	// Exclusive never replaces an existing file: the write then fails with an
	// error matching os.ErrExist and leaves that key untouched.
	Exclusive bool
}

// StoreSigningKeyFile retains each released path policy while sharing private
// bytes and atomic writes (docs/signature-primitives.md, Local private keys).
// Controller/team stores may use operator-managed mounted paths; identity keys
// retain their existing symlink preflight. Neither choice supplies authority.
func StoreSigningKeyFile(keyFile SigningKeyFile) error {
	switch keyFile.PathPolicy {
	case IdentityKeyPath:
		if err := preflightSigningKeyPath(keyFile.Path); err != nil {
			return err
		}
	case OperatorManagedAuthorityPath:
		// The operator supplies this authority-store path; retain its mount policy.
	default:
		return errors.New("unknown private-key path policy; select an identity or operator-managed authority destination")
	}
	if keyFile.Exclusive {
		if err := writePrivatePEM(privateKeyFile{Path: keyFile.Path, Kind: ed25519PrivateKey, Bytes: keyFile.Key.Seed(), Mode: createKeyExclusively}); err != nil {
			return exclusiveKeyWriteError(keyFile.Path, err)
		}
		return nil
	}
	return writePrivateKey(keyFile.Path, keyFile.Key)
}

// SaveSigningKeyExclusive writes a private signing key only when path does not
// already exist. It is used by recovery flows that must never overwrite
// recoverable identity material.
func SaveSigningKeyExclusive(path string, priv ed25519.PrivateKey) error {
	if err := preflightSigningKeyPath(path); err != nil {
		return err
	}
	if err := writePrivatePEM(privateKeyFile{Path: path, Kind: ed25519PrivateKey, Bytes: priv.Seed(), Mode: createKeyExclusively}); err != nil {
		return exclusiveKeyWriteError(path, err)
	}
	return nil
}

// exclusiveKeyWriteError words a failed exclusive write of the key at path.
// The key is put in place with a hard link, and a filesystem that has none
// refuses the link; that refusal is explained instead of left as the link's
// own error.
func exclusiveKeyWriteError(path string, err error) error {
	var link *os.LinkError
	if errors.As(err, &link) && (errors.Is(link.Err, syscall.EPERM) || errors.Is(link.Err, syscall.ENOTSUP) || errors.Is(link.Err, syscall.EOPNOTSUPP) || errors.Is(link.Err, syscall.EXDEV)) {
		return fmt.Errorf("create private key %s without overwrite: the filesystem holding %s does not support hard links; keep the identity home on a local filesystem: %w", path, path, err)
	}
	return fmt.Errorf("create private key %s without overwrite: %w", path, err)
}

// LoadSigningKey reads an Ed25519 private key from a PEM file.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	if err := preflightSigningKeyPath(path); err != nil {
		return nil, err
	}
	data, err := ReadPrivateKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	key, err := ParseSigningKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w in %s", err, path)
	}
	return key, nil
}

// ParseSigningKey reads an Ed25519 private key from its PEM bytes.
func ParseSigningKey(data []byte) (ed25519.PrivateKey, error) {
	seed, err := parsePrivatePEM(data, ed25519PrivateKey)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// parsePrivatePEM owns private-key PEM shape and size validation; algorithm
// constructors consume its decoded seed (docs/signature-primitives.md:96-99).
func parsePrivatePEM(data []byte, kind privateKeyKind) ([]byte, error) {
	var description string
	switch kind {
	case ed25519PrivateKey:
		description = "Ed25519"
	case x25519PrivateKey:
		description = "X25519"
	default:
		return nil, errors.New("unknown private-key PEM kind; select Ed25519 or X25519")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block; restore an %s private key PEM file", description)
	}
	if block.Type != string(kind) {
		return nil, fmt.Errorf("unexpected PEM type %q; restore an %s PEM file", block.Type, kind)
	}
	if len(block.Bytes) != 32 {
		return nil, fmt.Errorf("invalid seed size %d; restore a 32-byte %s private key seed", len(block.Bytes), description)
	}
	return block.Bytes, nil
}

func preflightSigningKeyPath(path string) error {
	return pathpreflight.PreflightFile(path, "signing key", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

// LoadPublicKey reads an Ed25519 public key from a PEM file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q in %s", block.Type, path)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size %d in %s", len(block.Bytes), path)
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// ArchiveKey writes a keypair to keysDir/rotated/ named by the old DID.
// Colons in the DID are replaced with dashes for filesystem compatibility.
func ArchiveKey(keysDir, oldDID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	rotatedDir := filepath.Join(keysDir, "rotated")
	if err := os.MkdirAll(rotatedDir, 0o700); err != nil {
		return fmt.Errorf("create rotated dir: %w", err)
	}

	base := didToKeyFileBase(oldDID)
	keyPath := filepath.Join(rotatedDir, base+".key")
	pubPath := filepath.Join(rotatedDir, base+".pub")

	if err := writePrivateKey(keyPath, priv); err != nil {
		return err
	}
	// Crash-test observation only; archive files form a separate durable pair.
	crashtest.Checkpoint("after-keypair-private-commit", keyPath)
	if err := writePublicKey(pubPath, pub); err != nil {
		return err
	}
	crashtest.Checkpoint("after-keypair-public-commit", pubPath)
	return nil
}

func writePrivateKey(path string, priv ed25519.PrivateKey) error {
	return writePrivatePEM(privateKeyFile{Path: path, Kind: ed25519PrivateKey, Bytes: priv.Seed(), Mode: replaceKeyAtomically})
}

func writePublicKey(path string, pub ed25519.PublicKey) error {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: []byte(pub),
	})
	if err := atomicWriteFileMode(path, data, 0o644); err != nil {
		return fmt.Errorf("write public key %s: %w", path, err)
	}
	return nil
}

// PublicKeyPath returns the sibling public-key PEM path for a signing key path.
func PublicKeyPath(signingKeyPath string) string {
	return strings.TrimSuffix(signingKeyPath, ".key") + ".pub"
}

// addressToKeyFileBase converts an agent address (e.g. "mycompany/researcher")
// to a filesystem-safe base name (e.g. "mycompany-researcher").
func addressToKeyFileBase(address string) string {
	return strings.ReplaceAll(address, "/", "-")
}

// didToKeyFileBase converts a DID string to a filesystem-safe base name
// by replacing colons with dashes.
func didToKeyFileBase(did string) string {
	return strings.ReplaceAll(did, ":", "-")
}

// KeySigner signs with key held in this process, such as the namespace
// controller key, as an IDCertificateSigner.
func KeySigner(key ed25519.PrivateKey) IDCertificateSigner {
	return func(payload []byte) (string, []byte, error) {
		return ComputeDIDKey(key.Public().(ed25519.PublicKey)), signaturewire.SignBytes(key, payload), nil
	}
}

// SigningKeyPath returns the path to an agent's signing key file.
func SigningKeyPath(keysDir, address string) string {
	return filepath.Join(keysDir, addressToKeyFileBase(address)+".signing.key")
}

// ReadPrivateKeyFile owns secret-file reads and compatibility diagnostics. It
// does not add symlink/owner refusals to readers that historically allowed
// mounted secrets. LoadSigningKey retains its existing path preflight.
func ReadPrivateKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	command, err := PrivateKeyPermissionFix(path)
	if err != nil {
		log.Printf("Could not inspect private key permissions for %s: %v. Check the file and mount permissions.", path, err)
		return data, nil
	}
	if command != "" {
		absolute, absErr := filepath.Abs(path)
		if absErr != nil {
			log.Printf("Could not resolve private key path for permission warning: %v. Check the working directory permissions.", absErr)
			absolute = path
		}
		if _, seen := warnedPrivateKeyPaths.LoadOrStore(absolute, true); !seen {
			if _, writeErr := fmt.Fprintf(os.Stderr, "Warning: private key %s is readable by group or others. Run %s.\n", path, command); writeErr != nil {
				log.Printf("Could not write private-key permission warning: %v. Check the command output destination.", writeErr)
			}
		}
	}
	return data, nil
}

var warnedPrivateKeyPaths sync.Map

// SupportsPOSIXPermissions reports whether mode bits describe access to private
// files. Windows profile ACLs govern access instead of POSIX group/other bits.
func SupportsPOSIXPermissions() bool { return runtime.GOOS != "windows" }

// PrivateKeyPermissionFix reports the exact remediation without reading bytes.
func PrivateKeyPermissionFix(path string) (string, error) {
	if !SupportsPOSIXPermissions() {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o044 == 0 {
		return "", nil
	}
	return PermissionFixCommand(path, 0o600)
}

// FixPrivateKeyPermissions changes only mode, leaving the key bytes intact.
func FixPrivateKeyPermissions(path string) error {
	if err := preflightSigningKeyPath(path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Private PEM types are internal; all callers use the single writer below.
type privateKeyKind string

const (
	ed25519PrivateKey privateKeyKind = "ED25519 PRIVATE KEY"
	x25519PrivateKey  privateKeyKind = "X25519 PRIVATE KEY"
)

type privateKeyWriteMode uint8

const (
	replaceKeyAtomically privateKeyWriteMode = iota
	createKeyExclusively
)

type privateKeyFile struct {
	Path  string
	Kind  privateKeyKind
	Bytes []byte
	Mode  privateKeyWriteMode
}

// writePrivatePEM is the single private PEM codec and writer (docs/signature-primitives.md).
// The key file is written atomically at 0600, always.
// A parent directory this writer creates has mode 0700.
// A parent directory that already exists is left as it is.
func writePrivatePEM(keyFile privateKeyFile) error {
	switch keyFile.Kind {
	case ed25519PrivateKey, x25519PrivateKey:
		if len(keyFile.Bytes) != 32 {
			return errors.New("private-key seed must contain 32 bytes; supply a valid Ed25519 or X25519 key")
		}
	default:
		return errors.New("unknown private-key PEM kind; select Ed25519 or X25519")
	}
	data := pem.EncodeToMemory(&pem.Block{Type: string(keyFile.Kind), Bytes: keyFile.Bytes})
	switch keyFile.Mode {
	case createKeyExclusively:
		return (atomicfile.Options{Mode: 0o600, ParentMode: 0o700, Exclusive: true}).Write(keyFile.Path, data)
	case replaceKeyAtomically:
		return atomicWritePrivateKeyFile(keyFile.Path, data)
	default:
		return errors.New("unknown private-key write mode; select atomic replacement or exclusive creation")
	}
}

// PermissionFixCommand quotes an exact local path without shell expansion.
func PermissionFixCommand(path string, mode os.FileMode) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	quoted := "'" + strings.ReplaceAll(absolute, "'", "'\\''") + "'"
	return "chmod " + strconv.FormatUint(uint64(mode), 8) + " " + quoted, nil
}
