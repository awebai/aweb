// Test-fixture writer using the actual protected-human record and encryption.
// The seed arrives only on a private stdin pipe; no plaintext key file is made.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"os"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// This filesystem HumanKeyStore is fixture storage, not an OS-keychain probe.
// The lab never reads it and reports custody not_tested. Encryption and record
// creation use the same implementations as the protected human initializer.
type encryptedFixtureStore struct{ path string }

func (s encryptedFixtureStore) LoadHumanKey(_ string) ([]byte, error) {
	return os.ReadFile(s.path)
}
func (s encryptedFixtureStore) SaveHumanKey(_ string, blob []byte) error {
	if err := awid.ValidateHumanKeyBackup(blob); err != nil {
		return err
	}
	return os.WriteFile(s.path, blob, 0600)
}

func main() {
	domain := flag.String("domain", "", "test namespace")
	registry := flag.String("registry", "", "test registry")
	certificate := flag.String("certificate", "", "public identity certificate ID")
	store := flag.String("keychain-file", "", "test encrypted-store destination")
	flag.Parse()
	if err := create(*domain, *registry, *certificate, *store); err != nil {
		os.Exit(1) // Never expose input, key, passphrase or crypto error internals.
	}
}

func create(domain, registry, certificate, store string) error {
	seed, err := io.ReadAll(io.LimitReader(os.Stdin, ed25519.SeedSize+1))
	if err != nil || len(seed) != ed25519.SeedSize {
		return io.ErrUnexpectedEOF
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
		for i := range key {
			key[i] = 0
		}
	}()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	passphrase := []byte(base64.StdEncoding.EncodeToString(random))
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()
	public := key.Public().(ed25519.PublicKey)
	id := awid.ComputeStableID(public)
	if err := awid.InstallHumanKey(encryptedFixtureStore{store}, id, key, passphrase); err != nil {
		return err
	}
	return awconfig.SaveHumanRecord(&awconfig.HumanRecord{
		StableID: id, DIDKey: awid.ComputeDIDKey(public), Domain: domain,
		RegistryURL: registry, State: awconfig.HumanRegistered,
		Path: awconfig.HumanPathRoot, CertificateID: certificate,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	})
}
