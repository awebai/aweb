package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

// humanRoleActRequest is one human-role act the team owner signs for an
// installed app: what the pinned manifest declares, the holding it names and,
// for designate and replace, the holder's public credential and team
// certificate (docs/owner-act-delivery.md).
type humanRoleActRequest struct {
	Act            string
	AppID          string
	Origin         string // owner_acts.origin, the act's audience
	Role           appmanifest.OwnerActRole
	InstallationID string
	Principal      string
	Credential     *awid.HumanCredential
	NoticeContact  string
	Certificate    string // the team certificate in X-AWID-Team-Certificate's encoding
}

func (r humanRoleActRequest) bindsCredential() bool { return r.Act != "human-role.revoke" }

func (r humanRoleActRequest) declaresNoticeContact() bool {
	return r.Role.NoticeContact != nil && *r.Role.NoticeContact
}

// check refuses, before anything is shown or signed, a request the route
// would refuse for its shape: an act the role does not declare, a credential
// or notice contact where the act or role does not take one, or a
// credential made for another host.
func (r humanRoleActRequest) check() error {
	if !slices.Contains(r.Role.Acts, r.Act) {
		return withErrorCode("act_not_declared", fmt.Errorf("%s declares no %s for role %s", r.AppID, r.Act, r.Role.Name))
	}
	if !r.bindsCredential() {
		if r.Credential != nil || r.Certificate != "" || r.NoticeContact != "" {
			return withErrorCode("credential_not_allowed", fmt.Errorf("%s takes no credential, certificate or notice contact", r.Act))
		}
		return nil
	}
	if r.Credential == nil || r.Certificate == "" {
		return withErrorCode("credential_required", fmt.Errorf("%s needs the holder's credential and team certificate", r.Act))
	}
	if (r.NoticeContact != "") != r.declaresNoticeContact() {
		if r.declaresNoticeContact() {
			return withErrorCode("notice_contact_mismatch", fmt.Errorf("role %s needs a notice contact", r.Role.Name))
		}
		return withErrorCode("notice_contact_mismatch", fmt.Errorf("role %s takes no notice contact", r.Role.Name))
	}
	if r.Credential.RPID == "aweb:" {
		return withErrorCode("security_key_unsupported", fmt.Errorf("aw does not bind a terminal security key (rp_id aweb:); use a browser passkey at the app's human origin"))
	}
	origin, err := url.Parse(r.Origin)
	if err != nil {
		return err
	}
	if r.Credential.RPID != origin.Hostname() {
		return withErrorCode("credential_rp_id_mismatch", fmt.Errorf("the credential was made for %s, not for %s", r.Credential.RPID, origin.Hostname()))
	}
	return nil
}

// subject is the act's subject, exactly as the route recomputes it.
func (r humanRoleActRequest) subject() (map[string]any, error) {
	subject := map[string]any{
		"app_id": r.AppID, "installation_id": r.InstallationID, "role": r.Role.Name, "principal": r.Principal,
	}
	if !r.bindsCredential() {
		return subject, nil
	}
	digest, err := r.Credential.SHA256()
	if err != nil {
		return nil, err
	}
	subject["credential_sha256"] = digest
	if r.NoticeContact != "" {
		contact := sha256.Sum256([]byte(r.NoticeContact))
		subject["notice_contact_sha256"] = hex.EncodeToString(contact[:])
	}
	return subject, nil
}

// deliveryBody is the body of POST <owner_acts.origin>/.well-known/aweb-owner-act.
func (r humanRoleActRequest) deliveryBody(signing []byte, signature string) map[string]any {
	body := map[string]any{"signing": base64.StdEncoding.EncodeToString(signing), "signature": signature}
	if r.bindsCredential() {
		body["credential"] = r.Credential
		body["certificate"] = r.Certificate
		if r.NoticeContact != "" {
			body["notice_contact"] = r.NoticeContact
		}
	}
	return body
}
