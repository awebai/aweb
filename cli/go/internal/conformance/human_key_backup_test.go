package conformance_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"testing"

	awid "github.com/awebai/aw/awid"
	"github.com/youmark/pkcs8"
)

type humanKeyBackupVector struct {
	Passphrase              string `json:"passphrase"`
	EncryptedPKCS8PEM       string `json:"encrypted_pkcs8_pem"`
	ExpectedPublicKey       string `json:"expected_public_key"`
	WrongPassphraseRefuses  bool   `json:"wrong_passphrase_refuses"`
	MinimumIterations       int    `json:"minimum_iterations"`
	WeakEncryptedPKCS8PEM   string `json:"weak_encrypted_pkcs8_pem"`
	WeakBackupExpectedError string `json:"weak_backup_expected_reason"`
}

func readHumanKeyBackupVector(t *testing.T) humanKeyBackupVector {
	t.Helper()
	var vectors struct {
		KeychainBackup humanKeyBackupVector `json:"keychain_backup"`
	}
	if err := json.Unmarshal(readRootVector(t, "id-certificates-v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors.KeychainBackup
}

func TestHumanKeyBackupImportsTheFrozenBackup(t *testing.T) {
	vector := readHumanKeyBackupVector(t)
	key, err := awid.ImportHumanKeyBackup([]byte(vector.EncryptedPKCS8PEM), []byte(vector.Passphrase))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if got := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)); got != vector.ExpectedPublicKey {
		t.Fatalf("imported key %s, want %s", got, vector.ExpectedPublicKey)
	}
}

func TestHumanKeyBackupWrongPassphraseRefuses(t *testing.T) {
	vector := readHumanKeyBackupVector(t)
	if !vector.WrongPassphraseRefuses {
		t.Fatal("vector no longer pins wrong-passphrase refusal")
	}
	key, err := awid.ImportHumanKeyBackup([]byte(vector.EncryptedPKCS8PEM), []byte("not-the-passphrase"))
	if err == nil || key != nil {
		t.Fatalf("wrong passphrase imported a key (err=%v)", err)
	}
}

func TestHumanKeyBackupBelowTheWorkFactorFloorRefuses(t *testing.T) {
	vector := readHumanKeyBackupVector(t)
	// The weak backup decrypts with the right passphrase, and still refuses.
	key, err := awid.ImportHumanKeyBackup([]byte(vector.WeakEncryptedPKCS8PEM), []byte(vector.Passphrase))
	if code := awid.HumanKeyBackupErrorCode(err); code != vector.WeakBackupExpectedError || key != nil {
		t.Fatalf("weak backup: code %q (err=%v), want %q", code, err, vector.WeakBackupExpectedError)
	}
	// Parameters are judged before any derivation: with a wrong passphrase
	// the refusal is still the work factor, not a failed decryption.
	_, err = awid.ImportHumanKeyBackup([]byte(vector.WeakEncryptedPKCS8PEM), []byte("not-the-passphrase"))
	if code := awid.HumanKeyBackupErrorCode(err); code != vector.WeakBackupExpectedError {
		t.Fatalf("weak backup with wrong passphrase: code %q (err=%v)", code, err)
	}
}

func TestHumanKeyBackupExportMeetsTheFloorAndRoundTrips(t *testing.T) {
	vector := readHumanKeyBackupVector(t)
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("export round trip")
	first, err := awid.ExportHumanKeyBackup(key, passphrase)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	second, err := awid.ExportHumanKeyBackup(key, passphrase)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	for _, backup := range [][]byte{first, second} {
		params := decodeBackup(t, backup)
		if params.iterations != vector.MinimumIterations || len(params.salt) != 16 || len(params.iv) != 16 {
			t.Fatalf("export parameters: %d iterations, %d-byte salt, %d-byte IV", params.iterations, len(params.salt), len(params.iv))
		}
		if !params.prf.Equal(oidHMACWithSHA256) || !params.cipher.Equal(oidAES256CBC) {
			t.Fatalf("export algorithms: prf %v, cipher %v", params.prf, params.cipher)
		}
		imported, err := awid.ImportHumanKeyBackup(backup, passphrase)
		if err != nil {
			t.Fatalf("import of export: %v", err)
		}
		if !bytes.Equal(imported, key) {
			t.Fatal("round trip changed the key")
		}
	}
	a, b := decodeBackup(t, first), decodeBackup(t, second)
	if bytes.Equal(a.salt, b.salt) || bytes.Equal(a.iv, b.iv) {
		t.Fatal("two exports reused a salt or IV")
	}
}

// Every other algorithm, missing parameter or malformed envelope refuses
// before derivation, with the right passphrase.
func TestHumanKeyBackupRefusesOtherParameters(t *testing.T) {
	vector := readHumanKeyBackupVector(t)
	cases := map[string]func(*backupEnvelope){
		"pbes1 scheme": func(e *backupEnvelope) {
			e.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
		},
		"scrypt kdf": func(e *backupEnvelope) {
			e.params.KDF.Algorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
		},
		"default hmac-sha1 prf": func(e *backupEnvelope) { e.kdf.PRF = pkix.AlgorithmIdentifier{} },
		"hmac-sha512 prf": func(e *backupEnvelope) {
			e.kdf.PRF = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}, Parameters: asn1.NullRawValue}
		},
		"aes-128-cbc cipher": func(e *backupEnvelope) {
			e.params.Cipher.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
		},
		"short salt":       func(e *backupEnvelope) { e.kdf.Salt = e.kdf.Salt[:15] },
		"short iv":         func(e *backupEnvelope) { e.iv = e.iv[:15] },
		"wrong key length": func(e *backupEnvelope) { e.kdf.KeyLength = 16 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			envelope := parseEnvelope(t, []byte(vector.EncryptedPKCS8PEM))
			mutate(&envelope)
			key, err := awid.ImportHumanKeyBackup(envelope.encode(t), []byte(vector.Passphrase))
			if err == nil || key != nil {
				t.Fatalf("%s imported a key", name)
			}
			// Refused by the parameter check itself, not by a failed decryption.
			if code := awid.HumanKeyBackupErrorCode(err); code != "unsupported_backup" {
				t.Fatalf("%s: code %q (err=%v)", name, code, err)
			}
		})
	}

	t.Run("one iteration below the floor", func(t *testing.T) {
		envelope := parseEnvelope(t, []byte(vector.EncryptedPKCS8PEM))
		envelope.kdf.Iterations = vector.MinimumIterations - 1
		_, err := awid.ImportHumanKeyBackup(envelope.encode(t), []byte(vector.Passphrase))
		if code := awid.HumanKeyBackupErrorCode(err); code != vector.WeakBackupExpectedError {
			t.Fatalf("code %q (err=%v)", code, err)
		}
	})

	// A hostile work factor must not hang a human-invoked import.
	t.Run("an implausibly large work factor", func(t *testing.T) {
		envelope := parseEnvelope(t, []byte(vector.EncryptedPKCS8PEM))
		envelope.kdf.Iterations = awid.HumanKeyBackupMaxIterations + 1
		_, err := awid.ImportHumanKeyBackup(envelope.encode(t), []byte(vector.Passphrase))
		if code := awid.HumanKeyBackupErrorCode(err); code != "unsupported_backup" {
			t.Fatalf("code %q (err=%v)", code, err)
		}
	})

	t.Run("the unmodified envelope still imports", func(t *testing.T) {
		envelope := parseEnvelope(t, []byte(vector.EncryptedPKCS8PEM))
		if _, err := awid.ImportHumanKeyBackup(envelope.encode(t), []byte(vector.Passphrase)); err != nil {
			t.Fatalf("re-encoded vector: %v", err)
		}
	})

	t.Run("trailing bytes after the envelope", func(t *testing.T) {
		envelope := parseEnvelope(t, []byte(vector.EncryptedPKCS8PEM))
		block, _ := pem.Decode(envelope.encode(t))
		block.Bytes = append(block.Bytes, 0)
		if _, err := awid.ImportHumanKeyBackup(pem.EncodeToMemory(block), []byte(vector.Passphrase)); err == nil {
			t.Fatal("trailing bytes imported")
		}
	})

	t.Run("a key that is not Ed25519", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := pkcs8.MarshalPrivateKey(ecKey, []byte(vector.Passphrase), &pkcs8.Opts{
			Cipher:  pkcs8.AES256CBC,
			KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: vector.MinimumIterations, HMACHash: crypto.SHA256},
		})
		if err != nil {
			t.Fatal(err)
		}
		backup := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
		if key, err := awid.ImportHumanKeyBackup(backup, []byte(vector.Passphrase)); err == nil || key != nil {
			t.Fatal("an ECDSA backup imported as a human key")
		}
	})

	t.Run("an unencrypted PKCS#8 key", func(t *testing.T) {
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x00}}
		if _, err := awid.ImportHumanKeyBackup(pem.EncodeToMemory(block), []byte(vector.Passphrase)); err == nil {
			t.Fatal("unencrypted key imported")
		}
	})
}

var (
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// The RFC 8018 structures, decoded independently of the code under test.
type pbkdf2Parameters struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

type pbes2Parameters struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type backupEnvelope struct {
	encryptedPrivateKeyInfo
	params pbes2Parameters
	kdf    pbkdf2Parameters
	iv     []byte
}

func parseEnvelope(t *testing.T, backup []byte) backupEnvelope {
	t.Helper()
	block, _ := pem.Decode(backup)
	if block == nil {
		t.Fatal("no PEM block")
	}
	var e backupEnvelope
	mustUnmarshal(t, block.Bytes, &e.encryptedPrivateKeyInfo)
	mustUnmarshal(t, e.Algorithm.Parameters.FullBytes, &e.params)
	mustUnmarshal(t, e.params.KDF.Parameters.FullBytes, &e.kdf)
	mustUnmarshal(t, e.params.Cipher.Parameters.FullBytes, &e.iv)
	return e
}

func (e backupEnvelope) encode(t *testing.T) []byte {
	t.Helper()
	e.params.KDF.Parameters = asn1.RawValue{FullBytes: mustMarshal(t, e.kdf)}
	e.params.Cipher.Parameters = asn1.RawValue{FullBytes: mustMarshal(t, e.iv)}
	e.Algorithm.Parameters = asn1.RawValue{FullBytes: mustMarshal(t, e.params)}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: mustMarshal(t, e.encryptedPrivateKeyInfo)})
}

type decodedBackup struct {
	iterations int
	salt, iv   []byte
	prf        asn1.ObjectIdentifier
	cipher     asn1.ObjectIdentifier
}

func decodeBackup(t *testing.T, backup []byte) decodedBackup {
	t.Helper()
	e := parseEnvelope(t, backup)
	if len(e.kdf.PRF.Algorithm) == 0 {
		t.Fatal("export omits the PRF (defaults to HMAC-SHA1)")
	}
	return decodedBackup{iterations: e.kdf.Iterations, salt: e.kdf.Salt, iv: e.iv, prf: e.kdf.PRF.Algorithm, cipher: e.params.Cipher.Algorithm}
}

func mustUnmarshal(t *testing.T, der []byte, out any) {
	t.Helper()
	rest, err := asn1.Unmarshal(der, out)
	if err != nil || len(rest) != 0 {
		t.Fatalf("asn1: %v (rest %d)", err, len(rest))
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
