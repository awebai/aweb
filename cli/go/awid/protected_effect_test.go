package awid

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedArtifactDigestPublicVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "protected-effect-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Signing   string `json:"artifact_signing_b64"`
		Signature string `json:"artifact_signature"`
		Digest    string `json:"artifact_sha256"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	signing, err := base64.StdEncoding.Strict().DecodeString(vector.Signing)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProtectedArtifactDigest(signing, vector.Signature)
	if err != nil || got != vector.Digest {
		t.Fatalf("%s %v", got, err)
	}
	signing = append(signing, ' ')
	changed, err := ProtectedArtifactDigest(signing, vector.Signature)
	if err != nil || changed == vector.Digest {
		t.Fatalf("changed artifact did not change digest: %s %v", changed, err)
	}
}
