package main

import (
	"fmt"
	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxStoredA2ATaskTokens = 50

// saveA2ATaskTokenBestEffort persists the task bearer token issued by the
// gateway so later `aw a2a status`/`aw a2a cancel` calls can present it.
// Without it, scoped routes correctly answer task_not_found to the async
// caller the contract tells to poll. Saving requires an existing .aw
// directory; otherwise the token is only printed.
func saveA2ATaskTokenBestEffort(rpcURL string, task a2a.Task) {
	taskID := strings.TrimSpace(task.ID)
	token, _ := task.Metadata["task_bearer_token"].(string)
	token = strings.TrimSpace(token)
	if taskID == "" || token == "" {
		return
	}
	if info, err := os.Stat(".aw"); err != nil || !info.IsDir() {
		return
	}
	path := filepath.Join(".aw", "a2a-credentials.yaml")
	var file a2aCredentialsFile
	if data, err := os.ReadFile(path); err == nil {
		_ = yaml.Unmarshal(data, &file)
	}
	kept := file.Credentials[:0]
	var taskEntries []a2aCredentialEntry
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) == "" {
			kept = append(kept, entry)
			continue
		}
		if strings.TrimSpace(entry.TaskID) == taskID {
			continue
		}
		taskEntries = append(taskEntries, entry)
	}
	taskEntries = append(taskEntries, a2aCredentialEntry{
		URL:       strings.TrimSpace(rpcURL),
		Host:      urlHost(rpcURL),
		TaskID:    taskID,
		TaskToken: token,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if len(taskEntries) > maxStoredA2ATaskTokens {
		taskEntries = taskEntries[len(taskEntries)-maxStoredA2ATaskTokens:]
	}
	file.Credentials = append(kept, taskEntries...)
	data, err := yaml.Marshal(file)
	if err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not persist task token: %v\n", err)
		return
	}
	// WriteFile only applies the mode on create; tighten pre-existing files.
	_ = os.Chmod(path, 0o600)
}

// loadA2ATaskTokenBestEffort returns the stored token for a specific task.
func loadA2ATaskTokenBestEffort(cardURL, rpcURL, taskID string) string {
	wd, _ := os.Getwd()
	return loadA2ATaskTokenBestEffortForDir(wd, cardURL, rpcURL, taskID)
}

func loadA2ATaskTokenBestEffortForDir(workingDir, cardURL, rpcURL, taskID string) string {
	data, err := os.ReadFile(filepath.Join(workingDir, ".aw", "a2a-credentials.yaml"))
	if err != nil {
		return ""
	}
	var file a2aCredentialsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return ""
	}
	cardHost := urlHost(cardURL)
	rpcHost := urlHost(rpcURL)
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) != strings.TrimSpace(taskID) {
			continue
		}
		host := strings.TrimSpace(entry.Host)
		url := strings.TrimSpace(entry.URL)
		if url == strings.TrimSpace(rpcURL) || url == strings.TrimSpace(cardURL) || host == cardHost || host == rpcHost {
			return strings.TrimSpace(entry.TaskToken)
		}
	}
	return ""
}

func loadA2ACredentialBestEffort(cardURL, rpcURL string) a2a.Credential {
	wd, _ := os.Getwd()
	return loadA2ACredentialBestEffortForDir(wd, cardURL, rpcURL)
}

func loadA2ACredentialBestEffortForDir(workingDir, cardURL, rpcURL string) a2a.Credential {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return a2a.Credential{}
	}
	path, err := awconfig.IdentityHomePath(home, "a2a-credentials.yaml")
	if err != nil {
		return a2a.Credential{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return a2a.Credential{}
	}
	var file a2aCredentialsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return a2a.Credential{}
	}
	cardHost := urlHost(cardURL)
	rpcHost := urlHost(rpcURL)
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) != "" {
			continue
		}
		if strings.TrimSpace(entry.URL) != "" && (strings.TrimSpace(entry.URL) == strings.TrimSpace(cardURL) || strings.TrimSpace(entry.URL) == strings.TrimSpace(rpcURL)) {
			return credentialFromEntry(entry)
		}
		if host := strings.TrimSpace(entry.Host); host != "" && (host == cardHost || host == rpcHost) {
			return credentialFromEntry(entry)
		}
	}
	return a2a.Credential{}
}

func credentialFromEntry(entry a2aCredentialEntry) a2a.Credential {
	return a2a.Credential{
		APIKey:      strings.TrimSpace(entry.APIKey),
		BearerToken: strings.TrimSpace(entry.BearerToken),
		CallerID:    strings.TrimSpace(entry.CallerID),
		TaskToken:   strings.TrimSpace(entry.TaskToken),
	}
}
