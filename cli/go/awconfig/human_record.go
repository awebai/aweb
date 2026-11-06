package awconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// A human's public records live outside every agent home, one directory per
// human ID under its domain: ~/.awid/humans/<domain>/<did:aw suffix>/. The
// directory holds identity.yaml, the installed id-chain.json and the human's
// own issuance log. The human key is only in the OS keychain; nothing secret
// is written here. A replacement human is a new ID, so it never overwrites
// another human's records.

// The states a human record moves through as `aw id human init` completes.
// Each step is retried from its record, never by minting again.
const (
	// HumanPrepared: the key is in the keychain and the record is written.
	HumanPrepared = "prepared"
	// HumanDIDRegistered: the did:aw key log is registered at AWID.
	HumanDIDRegistered = "did_registered"
	// HumanRegistered: AWID accepted the certificate and the chain is installed.
	HumanRegistered = "registered"
)

const (
	HumanPathRoot    = "root"
	HumanPathRequest = "request"
)

// HumanRecord is a human ID's public record.
type HumanRecord struct {
	StableID    string `yaml:"stable_id"`
	DIDKey      string `yaml:"did_key"`
	Domain      string `yaml:"domain"`
	RegistryURL string `yaml:"registry_url"`
	State       string `yaml:"state"`
	// Path is how the human is admitted: HumanPathRoot by this machine's
	// controller, or HumanPathRequest by an issuer elsewhere through the
	// request exchange. Each command resumes only its own path.
	Path string `yaml:"path,omitempty"`
	// CertificateID is the certificate the controller issued this human,
	// recorded in the controller's issuance log before it was released.
	CertificateID string `yaml:"certificate_id,omitempty"`
	// RegisteredAt is AWID's registration receipt time.
	RegisteredAt string `yaml:"registered_at,omitempty"`
}

var humanStableID = regexp.MustCompile(`^did:aw:([1-9A-HJ-NP-Za-km-z]+)$`)

// HumansDir holds the human records of domain.
func HumansDir(domain string) (string, error) {
	return PathInAWIDState("humans", NormalizeDomain(domain))
}

// HumanRecordDir is the directory of one human ID's records.
func HumanRecordDir(domain, stableID string) (string, error) {
	m := humanStableID.FindStringSubmatch(stableID)
	if m == nil {
		return "", fmt.Errorf("invalid human ID %q", stableID)
	}
	dir, err := HumansDir(domain)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, m[1]), nil
}

// ControllerIssuanceDir is the issuance log of the namespace controller of
// domain, beside its key: the certificates the root issued.
func ControllerIssuanceDir(domain string) (string, error) {
	dir, err := DefaultControllersDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, NormalizeDomain(domain)+".id-issuance"), nil
}

// SaveHumanRecord durably writes rec into its own directory.
func SaveHumanRecord(rec *HumanRecord) error {
	if rec == nil {
		return errors.New("nil human record")
	}
	dir, err := HumanRecordDir(rec.Domain, rec.StableID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(rec)
	if err != nil {
		return err
	}
	return durableWriteFile(filepath.Join(dir, "identity.yaml"), data)
}

// LoadHumanRecord returns the record of stableID in domain, or nil when there
// is none.
func LoadHumanRecord(domain, stableID string) (*HumanRecord, error) {
	dir, err := HumanRecordDir(domain, stableID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "identity.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec HumanRecord
	if err := yaml.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	if rec.StableID != stableID || NormalizeDomain(rec.Domain) != NormalizeDomain(domain) {
		return nil, fmt.Errorf("human record in %s names %s in %s", dir, rec.StableID, rec.Domain)
	}
	return &rec, nil
}

// HumanRecords lists the human records of domain, ordered by ID.
func HumanRecords(domain string) ([]*HumanRecord, error) {
	dir, err := HumansDir(domain)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := []*HumanRecord{}
	for _, name := range names {
		rec, err := LoadHumanRecord(domain, "did:aw:"+name)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, rec)
		}
	}
	return out, nil
}
