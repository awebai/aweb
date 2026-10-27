package awconfig

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
)

// InstalledIDChain is an identity's own ID chain, the one in force for it,
// validated whenever it is loaded.
type InstalledIDChain struct {
	Bundle map[string]any
	// Header is the bundle's X-AWID-ID-Chain value.
	Header string
}

func installedIDChainPath(identityHome string) string {
	return filepath.Join(identityHome, "id-chain.json")
}

// LoadInstalledIDChain returns the identity's installed chain, or nil when it
// has none. A damaged file is an error, never an absent chain.
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

// SaveInstalledIDChain validates bundle and durably installs it as the
// identity's chain.
func SaveInstalledIDChain(identityHome string, bundle map[string]any) error {
	header, err := awid.EncodeIDChainHeader(bundle)
	if err != nil {
		return err
	}
	canonical, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return err
	}
	return durableWriteFile(installedIDChainPath(identityHome), canonical)
}

// Subject is the authenticated subject the chain's leaf names, with the
// subject's current did:key. For a grant this is the grant subject's key,
// never the session's.
func (c *InstalledIDChain) Subject(currentDIDKey string) (awid.IDChainSubject, error) {
	certificates := c.Bundle["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	id := leaf["id"].(string)
	if strings.HasPrefix(id, "did:key:") && id != currentDIDKey {
		return awid.IDChainSubject{}, &awid.IDCertificateError{Code: "subject_mismatch"}
	}
	return awid.IDChainSubject{ID: id, DIDKey: currentDIDKey}, nil
}
