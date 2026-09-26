package main

import (
	"runtime"
	"testing"
)

func TestCLIUserAgentNamesTheBinaryVersionAndPlatform(t *testing.T) {
	previous := version
	version = "1.2.3"
	t.Cleanup(func() { version = previous })

	want := "aw/1.2.3 (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
	if got := cliUserAgent(); got != want {
		t.Fatalf("cliUserAgent() = %q, want %q", got, want)
	}
}
