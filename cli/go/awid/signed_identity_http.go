package awid

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

const (
	// HeaderRequestTimestamp carries the timestamp bound by request auth.
	HeaderRequestTimestamp = "X-AWEB-Timestamp"
	// HeaderSignedPayload carries the exact base64url v2 request envelope.
	HeaderSignedPayload = "X-AWEB-Signed-Payload"
	// HeaderTeamCertificate presents membership, independently of parentage.
	HeaderTeamCertificate = "X-AWID-Team-Certificate"
	// HeaderIDChain presents the identity's public parent certificates.
	HeaderIDChain = "X-AWID-ID-Chain"
	// HeaderIdentityID names the registered identity bound by identity auth.
	HeaderIdentityID = "X-AWEB-DID-AW"
)

// SignedIdentityPost contains an exact identity-authenticated JSON POST. Sign
// retains custody; Chain is optional public evidence, never authority supplied
// by the transport. Body is already canonicalized by the operation's owner.
type SignedIdentityPost struct {
	DIDKey    string
	StableID  string
	Sign      InteractiveSigner
	Target    *url.URL
	Timestamp string
	Body      []byte
	Chain     *IDChain
}

// NewSignedIdentityPostRequest binds the final target and owned body bytes with
// docs/aweb-sot.md §Request authentication's v2 identity profile. It performs no
// I/O and verifies the signer's answer before returning a request for transport.
func NewSignedIdentityPostRequest(ctx context.Context, input SignedIdentityPost) (*http.Request, error) {
	if input.Target == nil {
		return nil, fmt.Errorf("target URL is required")
	}
	target := *input.Target
	body := bytes.Clone(input.Body)
	chainHeader := ""
	if input.Chain != nil {
		header, err := input.Chain.Header()
		if err != nil {
			return nil, err
		}
		chainHeader = header
	}
	signature, payload, err := SignRequestCredentialWithSigner(input.DIDKey, input.Sign, http.MethodPost, &target, "did_aw", input.StableID, input.Timestamp, body, nil, "POST "+target.String())
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "DIDKey "+input.DIDKey+" "+signature)
	request.Header.Set(HeaderIdentityID, input.StableID)
	request.Header.Set(HeaderRequestTimestamp, input.Timestamp)
	request.Header.Set(HeaderSignedPayload, base64.RawURLEncoding.EncodeToString([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	if chainHeader != "" {
		request.Header.Set(HeaderIDChain, chainHeader)
	}
	return request, nil
}

// NewNoRedirectClient uses normal finite API timeouts and returns redirect
// responses to the caller. It never forwards a signed credential to Location.
func NewNoRedirectClient() *http.Client {
	return &http.Client{
		Timeout: APITimeout(), Transport: NewAPITransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
