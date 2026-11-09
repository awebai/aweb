package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// InteractiveSigner keeps key custody outside the client. The description is
// presented by the foreground human client on every signature; it is not a
// remote assertion of human presence.
type InteractiveSigner func(payload []byte, description string) (string, []byte, error)

// NewWithInteractiveSigner creates a root identity client without exporting its
// key. A nil certificate selects identity auth; a certificate selects team auth.
// Interactive clients support mail, not chat. Agent/grant constructors are unchanged.
func NewWithInteractiveSigner(baseURL, did string, cert *TeamCertificate, sign InteractiveSigner) (*Client, error) {
	if sign == nil {
		return nil, fmt.Errorf("interactive signer is required")
	}
	if _, err := ExtractPublicKey(did); err != nil {
		return nil, err
	}
	c, err := New(baseURL)
	if err != nil {
		return nil, err
	}
	c.did = did
	c.interactiveSigner = sign
	if cert != nil {
		if cert.MemberDIDKey != did {
			return nil, fmt.Errorf("certificate does not match selected signer")
		}
		header, err := EncodeTeamCertificateHeader(cert)
		if err != nil {
			return nil, err
		}
		c.teamCertHeader = header
		c.teamID = cert.Team
		c.certAlias = strings.TrimSpace(cert.Alias)
	}
	return c, nil
}

func checkedInteractiveSignature(did string, sign InteractiveSigner, payload []byte, description string) (string, error) {
	if sign == nil {
		return "", fmt.Errorf("interactive signer is required")
	}
	got, sig, err := sign(payload, description)
	if err != nil {
		return "", err
	}
	pub, err := ExtractPublicKey(did)
	if err != nil {
		return "", err
	}
	if got != did || !ed25519.Verify(pub, payload, sig) {
		return "", fmt.Errorf("interactive signature does not match selected identity")
	}
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

// SignRequestCredentialWithSigner uses exactly the ordinary v2 request bytes.
func SignRequestCredentialWithSigner(did string, sign InteractiveSigner, method string, target *url.URL, claim, value, timestamp string, body []byte, custom map[string]any, description string) (string, string, error) {
	payload, err := requestAuthPayload(method, target, claim, value, timestamp, body, custom)
	if err != nil {
		return "", "", err
	}
	sig, err := checkedInteractiveSignature(did, sign, payload, description)
	return sig, string(payload), err
}

func (c *Client) interactiveMailDescription(env *MessageEnvelope) string {
	sum := sha256.Sum256([]byte(env.Body))
	return fmt.Sprintf("mail to %q; subject %q; body sha256 %.12x", env.To, env.Subject, sum)
}
