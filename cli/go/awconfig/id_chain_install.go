package awconfig

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
)

// InstalledIDChain is an identity's own ID chain, the one in force for it.
// Loading checks its encoding, shape, limits and that each certificate's
// signature verifies under the issuer key it names. That is self-consistency,
// not authority: anything that relies on the chain verifies it with
// awid.VerifyIDChain against current status.
type InstalledIDChain struct {
	Bundle map[string]any
	// Header is the bundle's X-AWID-ID-Chain value.
	Header string
}

func installedIDChainPath(identityHome string) string {
	return filepath.Join(identityHome, "id-chain.json")
}

// LoadInstalledIDChain returns the identity's installed chain, or nil when it
// has none. A file that fails the checks is an error, never an absent chain.
func LoadInstalledIDChain(identityHome string) (*InstalledIDChain, error) {
	data, err := os.ReadFile(installedIDChainPath(identityHome))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	header := base64.RawURLEncoding.EncodeToString(data)
	bundle, err := awid.DecodeIDChainHeader(header)
	if err != nil {
		return nil, err
	}
	return &InstalledIDChain{Bundle: bundle, Header: header}, nil
}

// SaveInstalledIDChain applies the same checks to bundle and durably
// installs it as the identity's chain.
func SaveInstalledIDChain(identityHome string, bundle map[string]any) error {
	header, err := awid.EncodeIDChainHeader(bundle)
	if err != nil {
		return err
	}
	canonical, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return err
	}
	return atomicWriteFile(installedIDChainPath(identityHome), canonical)
}

// Subject is the authenticated subject the chain's leaf names, with the
// subject's current did:key. For a grant this is the grant subject's key,
// never the session's.
func (c *InstalledIDChain) Subject(currentDIDKey string) (awid.IDChainSubject, error) {
	leaf, err := c.Leaf()
	if err != nil {
		return awid.IDChainSubject{}, err
	}
	id := leaf.ID()
	if strings.HasPrefix(id, "did:key:") && id != currentDIDKey {
		return awid.IDChainSubject{}, &awid.IDCertificateError{Code: "subject_mismatch"}
	}
	return awid.IDChainSubject{ID: id, DIDKey: currentDIDKey}, nil
}

// Leaf returns a checked view of the subject certificate. It validates Bundle
// even for an InstalledIDChain built directly rather than loaded from disk.
func (c *InstalledIDChain) Leaf() (awid.IDCertificateView, error) {
	if c == nil {
		return awid.IDCertificateView{}, &awid.IDCertificateError{Code: "invalid_shape"}
	}
	chain, err := awid.IDChainFromBundle(c.Bundle)
	if err != nil {
		return awid.IDCertificateView{}, err
	}
	return chain.Leaf(), nil
}
