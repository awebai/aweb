package aweb

import (
	"crypto/ed25519"

	"github.com/awebai/aw/awid"
)

// Client provides both protocol and coordination operations.
// Protocol operations are available via the embedded awid.Client.
// Coordination operations (workspaces, team roles, tasks, reservations,
// claims) are defined as methods on this type.
type Client struct {
	*awid.Client
}

// New creates a client.
func New(baseURL string) (*Client, error) {
	c, err := awid.New(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

// NewWithCertificate creates a client authenticated with DIDKey signatures
// and a team certificate.
func NewWithCertificate(baseURL string, signingKey ed25519.PrivateKey, cert *awid.TeamCertificate) (*Client, error) {
	c, err := awid.NewWithCertificate(baseURL, signingKey, cert)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

// NewWithGrant creates a client authenticated as an identity-grant session,
// signing each request with the grant's session key.
func NewWithGrant(baseURL string, sessionKey ed25519.PrivateKey, grantID string) (*Client, error) {
	c, err := awid.NewWithGrant(baseURL, sessionKey, grantID)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}
