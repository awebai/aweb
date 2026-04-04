package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeContext struct {
	HumanAccount string `yaml:"human_account,omitempty"`
}

func DefaultWorktreeContextRelativePath() string {
	return filepath.Join(".aw", "context")
}

func FindWorktreeContextPath(startDir string) (string, error) {
	p := filepath.Join(filepath.Clean(startDir), DefaultWorktreeContextRelativePath())
	if _, err := os.Stat(p); err == nil {
		return p, nil
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

	data, err := yaml.Marshal(ctx)
	if err != nil {
		return err
	}

	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func bytesTrimRightNewlines(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), "\n"))
}
