package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

const maxStoredA2ATaskTokens = 50

type a2aCredentialQuery struct {
	CardURL string
	RPCURL  string
	TaskID  string
}

// readA2ACredentials distinguishes a missing optional file from an unreadable or
// malformed file. Refusing the latter also prevents a save from erasing it.
func readA2ACredentials(path string) (a2aCredentialsFile, error) {
	var file a2aCredentialsFile
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, fmt.Errorf("read A2A credentials: %w; repair the credential file and retry", err)
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		// YAML diagnostics may include credential values.
		return file, fmt.Errorf("A2A credential file %s is malformed. Repair its YAML and retry", path)
	}
	return file, nil
}

// saveA2ATaskToken keeps task access in the invoking instance's .aw directory;
// static credentials may belong to an independently selected identity home.
// Callers must still return the delivered task if local persistence fails.
func saveA2ATaskToken(rpcURL string, task a2a.Task) error {
	rawToken, exists := task.Metadata["task_bearer_token"]
	if !exists {
		return nil
	}
	token, ok := rawToken.(string)
	if !ok {
		return fmt.Errorf("gateway returned a task token with an invalid type. Repair the gateway before sending again")
	}
	token = strings.TrimSpace(token)
	taskID := strings.TrimSpace(task.ID)
	if taskID == "" || token == "" {
		return nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("locate task-token directory: %w", err)
	}
	return saveA2ATaskTokenInDirectory(a2aTokenSave{Directory: filepath.Join(wd, ".aw"), RPCURL: rpcURL, TaskID: taskID, Token: token})
}

type a2aTokenSave struct {
	Directory string
	RPCURL    string
	TaskID    string
	Token     string
}

func saveA2ATaskTokenInDirectory(input a2aTokenSave) (resultErr error) {
	info, err := os.Stat(input.Directory)
	if err != nil {
		return fmt.Errorf("open instance task-token directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("instance task-token path is not a directory")
	}
	// All task-token writers lock the same instance file before reading it.
	lock, err := awconfig.LockExclusive(filepath.Join(input.Directory, "a2a-credentials.lock"))
	if err != nil {
		return fmt.Errorf("lock A2A task tokens: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	path := filepath.Join(input.Directory, "a2a-credentials.yaml")
	file, err := readA2ACredentials(path)
	if err != nil {
		return err
	}
	kept := make([]a2aCredentialEntry, 0, len(file.Credentials)+1)
	var tasks []a2aCredentialEntry
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) == "" {
			kept = append(kept, entry)
			continue
		}
		if strings.TrimSpace(entry.TaskID) != input.TaskID {
			tasks = append(tasks, entry)
		}
	}
	tasks = append(tasks, a2aCredentialEntry{URL: strings.TrimSpace(input.RPCURL), Host: urlHost(input.RPCURL), TaskID: input.TaskID, TaskToken: input.Token, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	if len(tasks) > maxStoredA2ATaskTokens {
		tasks = tasks[len(tasks)-maxStoredA2ATaskTokens:]
	}
	file.Credentials = append(kept, tasks...)
	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("encode A2A task-token file: %w", err)
	}
	return atomicfile.Write(path, data, 0o600)
}

func loadA2ATaskToken(query a2aCredentialQuery) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("locate task-token directory: %w; run from an accessible directory and retry", err)
	}
	return loadA2ATaskTokenForDir(wd, query)
}

func loadA2ATaskTokenForDir(workingDir string, query a2aCredentialQuery) (string, error) {
	file, err := readA2ACredentials(filepath.Join(workingDir, ".aw", "a2a-credentials.yaml"))
	if err != nil {
		return "", err
	}
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) == strings.TrimSpace(query.TaskID) && matchesA2ACredential(entry, query) {
			return strings.TrimSpace(entry.TaskToken), nil
		}
	}
	return "", nil
}

func loadA2ACredential(query a2aCredentialQuery) (a2a.Credential, error) {
	wd, err := os.Getwd()
	if err != nil {
		return a2a.Credential{}, fmt.Errorf("locate A2A credentials: %w; run from an accessible directory and retry", err)
	}
	return loadA2ACredentialForDir(wd, query)
}

func loadA2ACredentialForDir(workingDir string, query a2aCredentialQuery) (a2a.Credential, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return a2a.Credential{}, fmt.Errorf("select A2A credential home: %w; select an accessible identity home and retry", err)
	}
	path, err := awconfig.IdentityHomePath(home, "a2a-credentials.yaml")
	if err != nil {
		return a2a.Credential{}, fmt.Errorf("locate A2A credential file: %w; select an accessible identity home and retry", err)
	}
	file, err := readA2ACredentials(path)
	if err != nil {
		return a2a.Credential{}, err
	}
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) == "" && matchesA2ACredential(entry, query) {
			return credentialFromEntry(entry), nil
		}
	}
	return a2a.Credential{}, nil
}

func matchesA2ACredential(entry a2aCredentialEntry, query a2aCredentialQuery) bool {
	endpoint := strings.TrimSpace(entry.URL)
	host := strings.TrimSpace(entry.Host)
	return endpoint != "" && (endpoint == strings.TrimSpace(query.CardURL) || endpoint == strings.TrimSpace(query.RPCURL)) || host != "" && (host == urlHost(query.CardURL) || host == urlHost(query.RPCURL))
}

func credentialFromEntry(entry a2aCredentialEntry) a2a.Credential {
	return a2a.Credential{APIKey: strings.TrimSpace(entry.APIKey), BearerToken: strings.TrimSpace(entry.BearerToken), CallerID: strings.TrimSpace(entry.CallerID), TaskToken: strings.TrimSpace(entry.TaskToken)}
}
