package main

import (
	"os"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv(awconfig.IdentityHomeEnv)
	os.Exit(m.Run())
}
