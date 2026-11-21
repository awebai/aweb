// Exercise the public pending/current team-key owner against a real registry.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/awebai/aw/awid"
)

type observationInput struct {
	RegistryURL string `json:"registry_url"`
	Certificate string `json:"certificate"`
}

type observationResult struct {
	Evidence *awid.TeamKeyEvidence           `json:"evidence,omitempty"`
	Code     awid.CurrentTeamCertificateCode `json:"code,omitempty"`
	Error    string                          `json:"error,omitempty"`
}

func observeTeamKey() observationResult {
	var input observationInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return observationResult{Error: fmt.Sprintf("decode probe input: %v", err)}
	}
	certificate, err := awid.DecodeTeamCertificateHeader(input.Certificate)
	if err != nil {
		return observationResult{Error: fmt.Sprintf("decode probe certificate: %v", err)}
	}
	registry := awid.NewAWIDRegistryClient(&http.Client{Timeout: 10 * time.Second}, nil)
	if err := registry.SetFallbackRegistryURL(input.RegistryURL); err != nil {
		return observationResult{Error: fmt.Sprintf("select registry: %v", err)}
	}
	// The probe's input is the operator-selected disposable registry origin.
	if err := registry.TrustRegistryOrigin(input.RegistryURL); err != nil {
		return observationResult{Error: fmt.Sprintf("trust selected registry: %v", err)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	observed, err := registry.CheckTeamCertificateCurrentKey(ctx, awid.CurrentTeamCertificateCheck{RegistryURL: input.RegistryURL, Certificate: certificate})
	if err != nil {
		result := observationResult{Error: err.Error()}
		var refusal *awid.CurrentTeamCertificateError
		if errors.As(err, &refusal) {
			result.Code = refusal.Code
		}
		return result
	}
	return observationResult{Evidence: &observed.Evidence}
}

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(observeTeamKey()); err != nil {
		fmt.Fprintln(os.Stderr, "encode probe result:", err)
		os.Exit(1)
	}
}
