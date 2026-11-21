package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/awebai/aw/awid"
)

const holderExportType = "aweb.human-role-credential"

const maxHolderExportBytes = 256 << 10

// holderCredentialExport is what a holder's aw hands the team owner's aw when
// they are different people: the public credential a credential handoff
// registered, with the holder's team certificate and ID chain as membership
// and kind evidence, and the holding they are for. Everything in it is
// public; the owner signs only after both clients show the same
// fingerprint.
type holderCredentialExport struct {
	V               int                  `json:"v"`
	Type            string               `json:"type"`
	AppID           string               `json:"app_id"`
	OwnerActsOrigin string               `json:"owner_acts_origin"`
	InstallationID  string               `json:"installation_id"`
	TeamID          string               `json:"team_id"`
	Role            string               `json:"role"`
	Principal       string               `json:"principal"`
	Credential      awid.HumanCredential `json:"credential"`
	Certificate     string               `json:"certificate"`
	IDChain         map[string]any       `json:"id_chain"`
}

// holderBinding is the holding an export must name to be used.
type holderBinding struct {
	AppID, OwnerActsOrigin, InstallationID, TeamID, Role, Principal string
}

func readHolderExport(path string) (*holderCredentialExport, error) {
	data, err := readFileBounded(path, maxHolderExportBytes)
	if err != nil {
		return nil, err
	}
	invalid := func(reason string) error {
		return withErrorCode("holder_export_invalid", fmt.Errorf("%s is not a holder credential export: %s", path, reason))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	// The ID chain's integers must stay json.Number: its canonical check
	// refuses a float64 as invalid_shape.
	decoder.UseNumber()
	var e holderCredentialExport
	if err := decoder.Decode(&e); err != nil {
		return nil, invalid(err.Error())
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid("trailing data")
	}
	if e.V != 1 || e.Type != holderExportType {
		return nil, invalid("unsupported version or type")
	}
	if _, err := e.Credential.SHA256(); err != nil {
		return nil, invalid(err.Error())
	}
	for name, value := range map[string]string{
		"app_id": e.AppID, "owner_acts_origin": e.OwnerActsOrigin, "installation_id": e.InstallationID,
		"team_id": e.TeamID, "role": e.Role, "principal": e.Principal, "certificate": e.Certificate,
	} {
		if value == "" {
			return nil, invalid(name + " is missing")
		}
	}
	if e.IDChain == nil {
		return nil, invalid("id_chain is missing")
	}
	return &e, nil
}

func writeHolderExport(path string, e holderCredentialExport) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// bindsTo refuses an export made for any other holding.
func (e holderCredentialExport) bindsTo(b holderBinding) error {
	got := holderBinding{e.AppID, e.OwnerActsOrigin, e.InstallationID, e.TeamID, e.Role, e.Principal}
	if got != b {
		return withErrorCode("holder_export_mismatch", fmt.Errorf("the export is for %s %s in %s (installation %s, %s), not for the holding being signed", got.Role, got.Principal, got.TeamID, got.InstallationID, got.OwnerActsOrigin))
	}
	return nil
}
