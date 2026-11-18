// Command proof exercises the production verifier with an external proof-only pin.
// It cannot install a binary or alter embedded production pins.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/internal/releaseverify"
)

func verifyProof(directory string) error {
	manifest, err := os.ReadFile(filepath.Join(directory, "release-manifest.json"))
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(filepath.Join(directory, "release-manifest.sig"))
	if err != nil {
		return err
	}
	pins, err := os.ReadFile(filepath.Join(directory, "proof-keys.json"))
	if err != nil {
		return err
	}
	var keys releaseverify.Keys
	if err := json.Unmarshal(pins, &keys); err != nil {
		return err
	}
	request := releaseverify.VerificationRequest{ManifestBytes: manifest, SignatureBytes: signature, Keys: keys, RequestedVersion: "0.0.0-rc.1", ArtifactName: "release-proof.bin"}
	artifact, err := releaseverify.Verify(request)
	if err != nil {
		return err
	}
	if err := releaseverify.VerifyFile(filepath.Join(directory, request.ArtifactName), artifact); err != nil {
		return err
	}
	fmt.Println("PASS Go: signed statement -> exact manifest -> artifact")
	request.ManifestBytes = append(append([]byte(nil), manifest...), '\n')
	if _, err := releaseverify.Verify(request); err == nil {
		return fmt.Errorf("Go accepted tampered manifest")
	}
	fmt.Println("PASS Go: tampered manifest refused")
	return nil
}

func main() {
	directory := flag.String("directory", "", "directory containing the throwaway proof files")
	flag.Parse()
	if *directory == "" {
		fmt.Fprintln(os.Stderr, "--directory is required")
		os.Exit(1)
	}
	if err := verifyProof(*directory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
