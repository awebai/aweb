package awid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	return writePublicKey(pubPath, pub)
}

// LoadSigningKey reads an Ed25519 private key from a PEM file.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q in %s", block.Type, path)
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size %d in %s", len(block.Bytes), path)
	}
	return ed25519.NewKeyFromSeed(block.Bytes), nil
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
	return writePublicKey(pubPath, pub)
}

func writePrivateKey(path string, priv ed25519.PrivateKey) error {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	})
	if err := atomicWriteFile(path, data); err != nil {
		return fmt.Errorf("write private key %s: %w", path, err)
	}
	return nil
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

// SigningKeyPath returns the path to an agent's signing key file.
func SigningKeyPath(keysDir, address string) string {
	return filepath.Join(keysDir, addressToKeyFileBase(address)+".signing.key")
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
