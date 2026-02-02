package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeContext struct {
	DefaultAccount string            `yaml:"default_account,omitempty"`
	ServerAccounts map[string]string `yaml:"server_accounts,omitempty"`
	HumanAccount   string            `yaml:"human_account,omitempty"`
}

func DefaultWorktreeContextRelativePath() string {
	return filepath.Join(".aw", "context")
}

func FindWorktreeContextPath(startDir string) (string, error) {
	dir := filepath.Clean(startDir)
	for {
		p := filepath.Join(dir, DefaultWorktreeContextRelativePath())
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}

func LoadWorktreeContextFrom(path string) (*WorktreeContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ctx WorktreeContext
	if err := yaml.Unmarshal(data, &ctx); err != nil {
		return nil, err
	}
	if ctx.ServerAccounts == nil {
		ctx.ServerAccounts = map[string]string{}
	}
	return &ctx, nil
}

func LoadWorktreeContextFromDir(startDir string) (*WorktreeContext, string, error) {
	p, err := FindWorktreeContextPath(startDir)
	if err != nil {
		return nil, "", err
	}
	ctx, err := LoadWorktreeContextFrom(p)
	if err != nil {
		return nil, "", err
	}
	return ctx, p, nil
}

func SaveWorktreeContextTo(path string, ctx *WorktreeContext) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if ctx.ServerAccounts == nil {
		ctx.ServerAccounts = map[string]string{}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := yaml.Marshal(ctx)
	if err != nil {
		return err
	}
	// Non-secret but keep private by default.
	return os.WriteFile(path, append(bytesTrimRightNewlines(data), '\n'), 0o600)
}

func bytesTrimRightNewlines(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), "\n"))
}
