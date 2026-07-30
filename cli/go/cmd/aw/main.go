package main

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
	Execute()
}
