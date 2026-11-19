package run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/atomicfile"
)

// LocalConfigState says what aw run does with the run.json of a directory.
//
// That file can set the agent's prompts and start commands, and the directory
// may be one the user did not write. It is used only when the user has trusted
// exactly its current content.
type LocalConfigState string

const (
	// LocalConfigAbsent: the directory has no run.json.
	LocalConfigAbsent LocalConfigState = "absent"
	// LocalConfigTrusted: the user trusted the file as it is now.
	LocalConfigTrusted LocalConfigState = "trusted"
	// LocalConfigUntrusted: the user never trusted the file.
	LocalConfigUntrusted LocalConfigState = "untrusted"
	// LocalConfigChanged: the file changed after the user trusted it.
	LocalConfigChanged LocalConfigState = "changed"
)

// IgnoredNote says, for a run.json that aw run did not use, why and what the
// user can do. It is empty for one that is absent or trusted.
func (state LocalConfigState) IgnoredNote(path string) string {
	const remedy = "Read it, then run aw run with --trust-config to use it as it is now."
	switch state {
	case LocalConfigUntrusted:
		return fmt.Sprintf(
			"aw run: ignoring %s: you have not trusted it. It can set the agent's prompts and start commands. %s",
			path, remedy,
		)
	case LocalConfigChanged:
		return fmt.Sprintf("aw run: ignoring %s: it changed since you trusted it. %s", path, remedy)
	default:
		return ""
	}
}

// trustedLocalConfigs is the user's record of the run.json files they trusted:
// the digest of each file's content, by the file's resolved path.
type trustedLocalConfigs struct {
	Files map[string]string `json:"files"`
}

func trustedLocalConfigsPath() (string, error) {
	return awconfig.PathInUserState("run-trusted.json")
}

func loadTrustedLocalConfigs() (trustedLocalConfigs, error) {
	trusted := trustedLocalConfigs{Files: map[string]string{}}
	path, err := trustedLocalConfigsPath()
	if err != nil {
		return trusted, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return trusted, nil
		}
		return trusted, err
	}
	if err := json.Unmarshal(data, &trusted); err != nil {
		return trusted, fmt.Errorf("parsing %s: %w", path, err)
	}
	if trusted.Files == nil {
		trusted.Files = map[string]string{}
	}
	return trusted, nil
}

// readLocalConfig returns the directory's run.json: its path, the key the
// trust record holds it under, and its content. found is false when the
// directory has none.
func readLocalConfig(startDir string) (path, key string, data []byte, found bool, err error) {
	path, err = FindLocalConfigPath(startDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil, false, nil
		}
		return "", "", nil, false, err
	}
	data, err = os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return path, "", nil, false, nil
		}
		return "", "", nil, false, err
	}
	key, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", nil, false, err
	}
	return path, key, data, true, nil
}

func localConfigDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// localConfigState reports the state of content read from the file at key.
func localConfigState(key string, data []byte) (LocalConfigState, error) {
	trusted, err := loadTrustedLocalConfigs()
	if err != nil {
		return "", err
	}
	digest, known := trusted.Files[key]
	switch {
	case !known:
		return LocalConfigUntrusted, nil
	case digest != localConfigDigest(data):
		return LocalConfigChanged, nil
	default:
		return LocalConfigTrusted, nil
	}
}

// LocalConfig reports the run.json of the directory and whether aw run uses it.
func LocalConfig(startDir string) (path string, state LocalConfigState, err error) {
	path, key, data, found, err := readLocalConfig(startDir)
	if err != nil {
		return "", "", err
	}
	if !found {
		return path, LocalConfigAbsent, nil
	}
	state, err = localConfigState(key, data)
	return path, state, err
}

// TrustLocalConfig records that the user trusts the directory's run.json as it
// is now, and returns its path and the digest of the content that was trusted.
func TrustLocalConfig(startDir string) (path, digest string, err error) {
	path, key, data, found, err := readLocalConfig(startDir)
	if err != nil {
		return "", "", err
	}
	if !found {
		return "", "", fmt.Errorf("no .aw/run.json to trust in %s", startDir)
	}
	trusted, err := loadTrustedLocalConfigs()
	if err != nil {
		return "", "", err
	}
	digest = localConfigDigest(data)
	trusted.Files[key] = digest
	encoded, err := json.MarshalIndent(trusted, "", "  ")
	if err != nil {
		return "", "", err
	}
	recordPath, err := trustedLocalConfigsPath()
	if err != nil {
		return "", "", err
	}
	if err := (atomicfile.Options{Mode: 0o600, ParentMode: 0o700}).Write(recordPath, append(encoded, '\n')); err != nil {
		return "", "", err
	}
	return path, digest, nil
}
