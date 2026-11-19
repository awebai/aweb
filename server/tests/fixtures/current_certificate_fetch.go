// Exercise the released Go SDK against the real registry listener in pytest.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/awebai/aw/awid"
)

type fetchInput struct {
	RegistryURL   string `json:"registry_url"`
	Domain        string `json:"domain"`
	Team          string `json:"team"`
	CertificateID string `json:"certificate_id"`
	MemberSeed    []byte `json:"member_seed"`
}

type fetchResult struct {
	CertificateID string                          `json:"certificate_id,omitempty"`
	Error         string                          `json:"error,omitempty"`
	Code          awid.CurrentTeamCertificateCode `json:"code,omitempty"`
}

func fetchCertificate() fetchResult {
	var input fetchInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return fetchResult{Error: fmt.Sprintf("decode probe input: %v", err)}
	}
	if len(input.MemberSeed) != ed25519.SeedSize {
		return fetchResult{Error: "probe member seed has the wrong length"}
	}
	key, err := awid.ParseSigningKey(pem.EncodeToMemory(&pem.Block{
		Type: "ED25519 PRIVATE KEY", Bytes: input.MemberSeed,
	}))
	if err != nil {
		return fetchResult{Error: fmt.Sprintf("parse probe member seed: %v", err)}
	}
	client := awid.NewAWIDRegistryClient(&http.Client{Timeout: 10 * time.Second}, nil)
	if err := client.SetFallbackRegistryURL(input.RegistryURL); err != nil {
		return fetchResult{Error: fmt.Sprintf("select registry: %v", err)}
	}
	// The probe's input is the operator-selected disposable registry origin.
	if err := client.TrustRegistryOrigin(input.RegistryURL); err != nil {
		return fetchResult{Error: fmt.Sprintf("trust selected registry: %v", err)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	certificate, err := client.FetchTeamCertificate(
		ctx, input.RegistryURL, input.Domain, input.Team, input.CertificateID,
		key,
	)
	if err != nil {
		result := fetchResult{Error: err.Error()}
		var refusal *awid.CurrentTeamCertificateError
		if errors.As(err, &refusal) {
			result.Code = refusal.Code
		}
		return result
	}
	return fetchResult{CertificateID: certificate.CertificateID}
}

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(fetchCertificate()); err != nil {
		fmt.Fprintln(os.Stderr, "encode probe result:", err)
		os.Exit(1)
	}
}
