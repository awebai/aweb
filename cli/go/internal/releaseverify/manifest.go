// Package releaseverify owns the signed release manifest verification rule.
// A bounded signing statement authenticates the exact manifest bytes.
package releaseverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/releaseversion"
)

// No production authority exists until Juan supplies actual public pins.
//
//go:embed keys.json
var pinnedKeys []byte

type Keys map[string]string

type Artifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type ManifestSchema string

const ReleaseManifestV1 ManifestSchema = "aw-release-manifest-v1"

type Manifest struct {
	Schema       ManifestSchema      `json:"schema"`
	Version      string              `json:"version"`
	SourceCommit string              `json:"source_commit"`
	Artifacts    map[string]Artifact `json:"artifacts"`
}
type Signature struct {
	Statement string `json:"statement"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func PinnedKeys() (Keys, error) {
	var keys Keys
	if err := json.Unmarshal(pinnedKeys, &keys); err != nil {
		return nil, fmt.Errorf("invalid embedded release keys.json: %w. Reinstall aw from a current verified release.", err)
	}
	if keys == nil {
		return nil, fmt.Errorf("embedded release keys.json must be an object. Reinstall aw from a current verified release.")
	}
	return keys, nil
}

var statementPattern = regexp.MustCompile(`^aw-release-statement-v1
version=(v?[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?)
source_commit=([0-9a-f]{40}(?:[0-9a-f]{24})?)
manifest_sha256=([0-9a-f]{64})
$`)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)

type VerificationRequest struct {
	ManifestBytes    []byte
	SignatureBytes   []byte
	Keys             Keys
	RequestedVersion string
	RunningVersion   string
	ArtifactName     string
}

// Verify implements docs/install-integrity.md:25-39 and :54-62.
// It authenticates the statement, then the exact manifest bytes, before interpreting fields.
// Both requested and current are lower bounds, preventing rollback by a mirror.
func Verify(request VerificationRequest) (Artifact, error) {
	raw, detached, keys := request.ManifestBytes, request.SignatureBytes, request.Keys
	requested, current, name := request.RequestedVersion, request.RunningVersion, request.ArtifactName
	refuse := func(reason string) (Artifact, error) {
		return Artifact{}, fmt.Errorf("cannot verify %s: %s. Retry the installer or aw upgrade from a current signed release.", name, reason)
	}
	var signature Signature
	if validateUniqueJSON(detached) != nil || json.Unmarshal(detached, &signature) != nil {
		return refuse("invalid release-manifest.sig")
	}
	public, err := base64.StdEncoding.DecodeString(keys[signature.KeyID])
	if err != nil || len(public) != ed25519.PublicKeySize {
		return refuse("release signing key is not pinned")
	}
	statement, err := base64.StdEncoding.DecodeString(signature.Statement)
	if err != nil || len(statement) > 256 {
		return refuse("invalid bounded release statement")
	}
	sig, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || awid.VerifyDetachedSignature(awid.DetachedSignature{PublicKey: public, Signature: sig, Payload: statement}) != nil {
		return refuse("invalid publisher signature")
	}
	fields := statementPattern.FindSubmatch(statement)
	if fields == nil {
		return refuse("invalid canonical release statement")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != string(fields[3]) {
		return refuse("release manifest digest does not match signed statement")
	}
	var manifest Manifest
	if validateUniqueJSON(raw) != nil || json.Unmarshal(raw, &manifest) != nil || len(manifest.Artifacts) == 0 || manifest.Schema != ReleaseManifestV1 || !commitPattern.MatchString(manifest.SourceCommit) {
		return refuse("invalid release-manifest.json")
	}
	if manifest.Version != string(fields[1]) || manifest.SourceCommit != string(fields[2]) {
		return refuse("release statement version or source commit differs from manifest")
	}
	for _, floor := range []string{requested, current} {
		if floor == "" || floor == "dev" {
			continue
		}
		order, valid := releaseversion.Compare(manifest.Version, floor)
		if !valid || order < 0 {
			return refuse("release manifest is older than requested or running version")
		}
	}
	if order, valid := releaseversion.Compare(manifest.Version, requested); !valid || order != 0 {
		return refuse("release manifest version does not match requested version")
	}
	for filename, artifact := range manifest.Artifacts {
		digest, err := hex.DecodeString(artifact.SHA256)
		if filename == "" || path.Base(filename) != filename || strings.ContainsAny(filename, "\\\r\n") || err != nil || len(digest) != sha256.Size || artifact.Size < 0 {
			return refuse("invalid artifact entry")
		}
	}
	artifact, ok := manifest.Artifacts[name]
	if !ok {
		return refuse("artifact is absent from the signed manifest")
	}
	return artifact, nil
}

func VerifyFile(filename string, expected Artifact) (err error) {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, expected.Size+1))
	if err != nil {
		return err
	}
	if n != expected.Size || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(expected.SHA256) {
		return fmt.Errorf("digest mismatch for %s. Retry the installer or aw upgrade to download a fresh archive.", path.Base(filename))
	}
	return nil
}
