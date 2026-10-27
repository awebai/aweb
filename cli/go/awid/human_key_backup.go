package awid

// The one v1 multi-machine method for a human key (docs/id-certificates.md
// §3, "Human key lifecycle and two machines"): an encrypted PKCS#8 export of
// the same Ed25519 key, PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC.
import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"github.com/youmark/pkcs8"
)

const (
	HumanKeyBackupMinIterations = 600000
	// HumanKeyBackupMaxIterations bounds the work a hostile backup can demand.
	HumanKeyBackupMaxIterations = 10000000
	humanKeyBackupSaltBytes     = 16
	humanKeyBackupIVBytes       = 16
	humanKeyBackupKeyBytes      = 32
	humanKeyBackupPEMType       = "ENCRYPTED PRIVATE KEY"
)

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// HumanKeyBackupError carries a stable refusal code, independent of prose.
type HumanKeyBackupError struct{ Code string }

func (e *HumanKeyBackupError) Error() string { return e.Code }

func humanKeyBackupRefusal(code string) error { return &HumanKeyBackupError{Code: code} }

// HumanKeyBackupErrorCode returns the refusal code of err, or "".
func HumanKeyBackupErrorCode(err error) string {
	var e *HumanKeyBackupError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ExportHumanKeyBackup encrypts key at the contract's work factor with a
// fresh random salt and IV. The library's defaults are below the floor and
// are never used.
func ExportHumanKeyBackup(key ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	der, err := pkcs8.MarshalPrivateKey(key, passphrase, &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       humanKeyBackupSaltBytes,
			IterationCount: HumanKeyBackupMinIterations,
			HMACHash:       crypto.SHA256,
		},
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: humanKeyBackupPEMType, Bytes: der}), nil
}

// ImportHumanKeyBackup decrypts an exported human key. Its algorithms and
// work factor are checked before any key derivation, so a weak backup
// refuses even when the passphrase would decrypt it.
func ImportHumanKeyBackup(backup, passphrase []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(backup)
	if block == nil {
		return nil, humanKeyBackupRefusal("unsupported_backup")
	}
	if err := checkHumanKeyBackupParameters(block.Bytes); err != nil {
		return nil, err
	}
	parsed, _, err := pkcs8.ParsePrivateKey(block.Bytes, passphrase)
	if err != nil {
		return nil, humanKeyBackupRefusal("backup_decryption_failed")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, humanKeyBackupRefusal("unsupported_backup")
	}
	return key, nil
}

type humanKeyBackupInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type humanKeyBackupPBES2 struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

type humanKeyBackupPBKDF2 struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

func checkHumanKeyBackupParameters(der []byte) error {
	unsupported := humanKeyBackupRefusal("unsupported_backup")
	var info humanKeyBackupInfo
	if !unmarshalExactly(der, &info) || !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return unsupported
	}
	var scheme humanKeyBackupPBES2
	if !unmarshalExactly(info.Algorithm.Parameters.FullBytes, &scheme) {
		return unsupported
	}
	if !scheme.KDF.Algorithm.Equal(oidPBKDF2) || !scheme.Cipher.Algorithm.Equal(oidAES256CBC) {
		return unsupported
	}
	var kdf humanKeyBackupPBKDF2
	if !unmarshalExactly(scheme.KDF.Parameters.FullBytes, &kdf) {
		return unsupported
	}
	// An absent PRF means the RFC 8018 default, HMAC-SHA1.
	if !kdf.PRF.Algorithm.Equal(oidHMACWithSHA256) {
		return unsupported
	}
	if len(kdf.Salt) < humanKeyBackupSaltBytes || (kdf.KeyLength != 0 && kdf.KeyLength != humanKeyBackupKeyBytes) {
		return unsupported
	}
	var iv []byte
	if !unmarshalExactly(scheme.Cipher.Parameters.FullBytes, &iv) || len(iv) != humanKeyBackupIVBytes {
		return unsupported
	}
	if kdf.Iterations > HumanKeyBackupMaxIterations {
		return unsupported
	}
	if kdf.Iterations < HumanKeyBackupMinIterations {
		return humanKeyBackupRefusal("weak_backup_kdf")
	}
	return nil
}

func unmarshalExactly(der []byte, out any) bool {
	rest, err := asn1.Unmarshal(der, out)
	return err == nil && len(rest) == 0
}
