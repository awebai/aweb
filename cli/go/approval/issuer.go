package approval

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
)

// IdentityIssuerClient carries a person's own covering request to their issuer.
// The shared awid signer owns the v2 envelope; the issuer establishes authority.
// HTTP and Sign retain their host's custody and transport ownership.
type IdentityIssuerClient struct {
	Origin        string
	Person        string
	DIDKey        string
	Sign          awid.InteractiveSigner
	IDChain       map[string]any
	HTTP          *http.Client
	ResponseLimit int64
}

// IssuerPostInput names the issuer endpoint and exact JSON value to be covered.
type IssuerPostInput struct {
	Path string
	Body any
}

// CanonicalIssuerOrigin uses the shared service-origin rule and requires HTTPS.
// Registry origin selection and administrative network trust are separate rules.
func CanonicalIssuerOrigin(value string) (string, error) {
	origin, err := awid.CanonicalServerOrigin(value)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(origin)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return "", errors.New("The issuer must be an HTTPS origin. Ask its operator for the HTTPS origin and retry.")
	}
	return origin, nil
}

// Post signs once, sends once without redirects, and reads a bounded response.
// It never interprets an issuer refusal as an approval-service decision.
func (c *IdentityIssuerClient) Post(ctx context.Context, in IssuerPostInput) (*HTTPAnswer, error) {
	origin, err := CanonicalIssuerOrigin(c.Origin)
	if err != nil {
		return nil, err
	}
	if c.ResponseLimit <= 0 {
		return nil, errors.New("Configure a positive issuer response size limit before sending this request.")
	}
	target, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	target.Path = in.Path
	raw, err := proof.Canonical(in.Body)
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature, payload, err := awid.SignRequestCredentialWithSigner(c.DIDKey, c.Sign, http.MethodPost, target, "did_aw", c.Person, timestamp, raw, nil, "POST "+target.String())
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "DIDKey "+c.DIDKey+" "+signature)
	request.Header.Set("X-AWEB-DID-AW", c.Person)
	request.Header.Set("X-AWEB-Timestamp", timestamp)
	request.Header.Set("X-AWEB-Signed-Payload", base64.RawURLEncoding.EncodeToString([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	if c.IDChain != nil {
		header, err := awid.EncodeIDChainHeader(c.IDChain)
		if err != nil {
			return nil, err
		}
		request.Header.Set("X-AWID-ID-Chain", header)
	}
	return sendApprovalRequest(approvalHTTPRequest{Request: request, Client: c.HTTP, ResponseLimit: c.ResponseLimit})
}
