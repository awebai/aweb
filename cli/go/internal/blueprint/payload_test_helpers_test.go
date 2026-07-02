package blueprint

import (
	"crypto/sha256"
	"encoding/hex"
)

func withPayloadFileSHA(files []LibraryProfilePayloadFile) []LibraryProfilePayloadFile {
	out := make([]LibraryProfilePayloadFile, len(files))
	for i, file := range files {
		sum := sha256.Sum256([]byte(file.ContentUTF8))
		file.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
		out[i] = file
	}
	return out
}
