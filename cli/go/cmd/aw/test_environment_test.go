package main

import (
	"os"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv(awconfig.IdentityHomeEnv)
	// Channel setup installs the aweb-channel plugin at user scope, which is
	// shared by every agent on the host and is not something running the unit
	// tests should touch. Neutralize it for the package so reaching the setup
	// path is inert by default; tests that assert on the commands install their
	// own recorder.
	runClaudeChannelPluginCommand = func(args ...string) error { return nil }
	os.Exit(m.Run())
}
