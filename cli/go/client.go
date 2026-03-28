package aweb

import (
	"crypto/ed25519"

	"github.com/awebai/aw/awid"
)

// Client provides both protocol and coordination operations.
// Protocol operations are available via the embedded awid.Client.
// Coordination operations (workspaces, project roles, tasks, reservations,
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

// NewWithAPIKey creates an authenticated client.
func NewWithAPIKey(baseURL, apiKey string) (*Client, error) {
	c, err := awid.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

// NewWithIdentity creates an authenticated client with signing capability.
func NewWithIdentity(baseURL, apiKey string, signingKey ed25519.PrivateKey, did string) (*Client, error) {
	c, err := awid.NewWithIdentity(baseURL, apiKey, signingKey, did)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}
