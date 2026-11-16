package awid

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// SignedArtifactDigest binds the exact bytes of a historical signed result.
// The input signature is canonical unpadded standard base64, never a new signing
// interface. A digest is not proof of service authority or remote application.
func SignedArtifactDigest(signing []byte, signature string) (string, error) {
	if strings.ContainsAny(signature, "\r\n=") {
		return "", fmt.Errorf("invalid protected artifact signature")
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(signature)
	if err != nil || len(raw) != 64 {
		return "", fmt.Errorf("invalid protected artifact signature")
	}
	sum := sha256.New()
	sum.Write([]byte("aweb.protected-artifact/1\n"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(signing)))
	sum.Write(size[:])
	sum.Write(signing)
	sum.Write(raw)
	return hex.EncodeToString(sum.Sum(nil)), nil
}
