package awid

// Local message logs sealed to a team's owner log key. Each log line is
// encrypted on its own to the owner's X25519 public key with the same HPKE
// suite as E2EE key wraps, so an agent can append to its log but cannot read
// it back; only the holder of the owner's private key can. The public key
// reaches agent hosts as a record signed by the team controller key, and is
// used only after that signature verifies under the team's did:key.
import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// LogKeyRecordPrefix domain-separates log-key records: no team certificate,
// owner act or other team-key-signed object verifies as one.
const LogKeyRecordPrefix = "aweb.log-key/1\n"

const (
	logKeyRecordVersion  = 1
	sealedLogLineVersion = 1
	sealedLogLineInfo    = "aweb.local-log/1"
)

// LogKeyRecord is the owner-signed public half of a team's log key.
type LogKeyRecord struct {
	V          int    `json:"v"`
	TeamID     string `json:"team_id"`
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at"`
	TeamKeyDID string `json:"team_key_did"`
	Signature  string `json:"signature"`
}

// LogKeyPair is an owner log key as generated on the owner's machine.
type LogKeyPair struct {
	Private *ecdh.PrivateKey
	Public  []byte
}

// PublicKeyText is the public key as carried in a LogKeyRecord.
func (p *LogKeyPair) PublicKeyText() string {
	return encodeLogBytes(p.Public)
}

// KeyID identifies the key in records, sealed lines and the owner's keychain.
func (p *LogKeyPair) KeyID() (string, error) {
	return ComputeEncryptionKeyID(p.Public)
}

// SealedLogLine is one encrypted log entry. Only the version, the key that
// can open it and an optional caller tag are visible; the tag is bound to the
// ciphertext.
type SealedLogLine struct {
	V      int    `json:"v"`
	KeyID  string `json:"key_id"`
	Tag    string `json:"tag,omitempty"`
	Enc    string `json:"enc"`
	Sealed string `json:"ct"`
}

func GenerateLogKeyPair() (*LogKeyPair, error) {
	priv, pub, err := GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}
	return &LogKeyPair{Private: priv, Public: pub}, nil
}

// NewLogKeyRecord is the unsigned record for publicKey in teamID.
func NewLogKeyRecord(teamID string, publicKey []byte, now time.Time) (*LogKeyRecord, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return nil, errors.New("log key record requires a team id")
	}
	keyID, err := ComputeEncryptionKeyID(publicKey)
	if err != nil {
		return nil, err
	}
	return &LogKeyRecord{
		V:         logKeyRecordVersion,
		TeamID:    teamID,
		KeyID:     keyID,
		PublicKey: encodeLogBytes(publicKey),
		CreatedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
	}, nil
}

// SignLogKeyRecord signs rec with the team controller key and names that key.
func SignLogKeyRecord(rec *LogKeyRecord, teamKey ed25519.PrivateKey) error {
	if rec == nil {
		return errors.New("missing log key record")
	}
	if len(teamKey) != ed25519.PrivateKeySize {
		return errors.New("team controller key is required")
	}
	rec.TeamKeyDID = ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	payload, err := logKeyRecordSignedPayload(rec)
	if err != nil {
		return err
	}
	rec.Signature = encodeLogBytes(ed25519.Sign(teamKey, payload))
	return nil
}

// VerifyLogKeyRecord accepts rec only as teamID's log key signed by the team
// key teamDIDKey, with a key id that matches its public key.
func VerifyLogKeyRecord(rec *LogKeyRecord, teamID, teamDIDKey string) error {
	if rec == nil {
		return errors.New("missing log key record")
	}
	if rec.V != logKeyRecordVersion {
		return fmt.Errorf("unsupported log key record version %d", rec.V)
	}
	if strings.TrimSpace(teamID) == "" || rec.TeamID != strings.TrimSpace(teamID) {
		return fmt.Errorf("log key record is for team %q, not %q", rec.TeamID, teamID)
	}
	if rec.TeamKeyDID != strings.TrimSpace(teamDIDKey) {
		return errors.New("log key record is not signed by this team's key")
	}
	teamPub, err := ExtractPublicKey(teamDIDKey)
	if err != nil {
		return fmt.Errorf("team key: %w", err)
	}
	if _, err := rec.publicKey(); err != nil {
		return err
	}
	signature, err := decodeLogBytes(rec.Signature)
	if err != nil {
		return fmt.Errorf("log key record signature: %w", err)
	}
	payload, err := logKeyRecordSignedPayload(rec)
	if err != nil {
		return err
	}
	if !ed25519.Verify(teamPub, payload, signature) {
		return errors.New("log key record signature does not verify")
	}
	return nil
}

func (rec *LogKeyRecord) publicKey() ([]byte, error) {
	raw, err := decodeLogBytes(rec.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("log key public key: %w", err)
	}
	keyID, err := ComputeEncryptionKeyID(raw)
	if err != nil {
		return nil, err
	}
	if keyID != rec.KeyID {
		return nil, errors.New("log key id does not match its public key")
	}
	return raw, nil
}

func logKeyRecordSignedPayload(rec *LogKeyRecord) ([]byte, error) {
	canonical, err := CanonicalJSONValue(map[string]any{
		"v":            rec.V,
		"team_id":      rec.TeamID,
		"key_id":       rec.KeyID,
		"public_key":   rec.PublicKey,
		"created_at":   rec.CreatedAt,
		"team_key_did": rec.TeamKeyDID,
	})
	if err != nil {
		return nil, err
	}
	return []byte(LogKeyRecordPrefix + canonical), nil
}

// SealLogLine encrypts plaintext to rec's public key. The caller has verified
// rec with VerifyLogKeyRecord.
func SealLogLine(rec *LogKeyRecord, tag string, plaintext []byte) (*SealedLogLine, error) {
	if rec == nil {
		return nil, errors.New("missing log key record")
	}
	pub, err := rec.publicKey()
	if err != nil {
		return nil, err
	}
	line := &SealedLogLine{V: sealedLogLineVersion, KeyID: rec.KeyID, Tag: tag}
	aad, err := sealedLogLineAAD(line)
	if err != nil {
		return nil, err
	}
	enc, ciphertext, err := hpkeBaseSealX25519AES256GCM(pub, []byte(sealedLogLineInfo), aad, plaintext)
	if err != nil {
		return nil, err
	}
	line.Enc = encodeLogBytes(enc)
	line.Sealed = encodeLogBytes(ciphertext)
	return line, nil
}

// OpenLogLine decrypts line with the owner's private log key.
func OpenLogLine(line *SealedLogLine, priv *ecdh.PrivateKey) ([]byte, error) {
	if line == nil {
		return nil, errors.New("missing sealed log line")
	}
	if line.V != sealedLogLineVersion {
		return nil, fmt.Errorf("unsupported sealed log line version %d", line.V)
	}
	enc, err := decodeLogBytes(line.Enc)
	if err != nil {
		return nil, fmt.Errorf("sealed log line enc: %w", err)
	}
	ciphertext, err := decodeLogBytes(line.Sealed)
	if err != nil {
		return nil, fmt.Errorf("sealed log line ct: %w", err)
	}
	aad, err := sealedLogLineAAD(line)
	if err != nil {
		return nil, err
	}
	plaintext, err := hpkeBaseOpenX25519AES256GCM(priv, enc, []byte(sealedLogLineInfo), aad, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("open sealed log line: %w", err)
	}
	return plaintext, nil
}

func sealedLogLineAAD(line *SealedLogLine) ([]byte, error) {
	canonical, err := CanonicalJSONValue(map[string]any{"v": line.V, "key_id": line.KeyID, "tag": line.Tag})
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

// ExportLogKeyBackup writes the owner's private log key as an encrypted
// backup in the same frozen format as a human key backup.
func ExportLogKeyBackup(priv *ecdh.PrivateKey, passphrase []byte) ([]byte, error) {
	if priv == nil || priv.Curve() != ecdh.X25519() {
		return nil, errors.New("log key must be an X25519 private key")
	}
	return exportKeyBackup(priv, passphrase)
}

// ImportLogKeyBackup decrypts a backup made by ExportLogKeyBackup.
func ImportLogKeyBackup(backup, passphrase []byte) (*ecdh.PrivateKey, error) {
	parsed, err := importKeyBackup(backup, passphrase)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return nil, humanKeyBackupRefusal("unsupported_backup")
	}
	return priv, nil
}

func encodeLogBytes(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

func decodeLogBytes(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.TrimSpace(s))
}
