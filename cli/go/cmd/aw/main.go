package main

import (
	"fmt"
	"runtime"

	"github.com/awebai/aw/awid"
)

// Set by goreleaser ldflags.
//
// commit is stamped by goreleaser running in the repository the release is built
// from, which is not necessarily the repository this source is read in. commitRepo
// names that repository so the hash can be resolved; it is empty for any build that
// did not set it, and the output then claims no origin rather than guessing one.
var (
	version    = "dev"
	commit     = "none"
	commitRepo = ""
	date       = "unknown"
)

func main() {
	awid.SetDefaultUserAgent(cliUserAgent())
	Execute()
}

// cliUserAgent names this binary and its version on every request that sets no
// more specific User-Agent, so the server can see which CLI versions call it.
func cliUserAgent() string {
	return fmt.Sprintf("aw/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}
