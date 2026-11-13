package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

type humanRoleDeliveryCase struct {
	Name string `json:"name"`
	Act  struct {
		Act     string         `json:"act"`
		Subject map[string]any `json:"subject"`
	} `json:"act"`
	App struct {
		AppID           string                   `json:"app_id"`
		OwnerActsOrigin string                   `json:"owner_acts_origin"`
		Role            appmanifest.OwnerActRole `json:"role"`
	} `json:"app"`
	Body            map[string]any `json:"body"`
	ExpectedSubject map[string]any `json:"expected_subject"`
	Result          struct {
		Status int `json:"status"`
	} `json:"result"`
}

// acceptedHumanRoleCases are the delivery vector's human-role acts that the
// route accepts: the requests a correct client sends.
func acceptedHumanRoleCases(t *testing.T) []humanRoleDeliveryCase {
	t.Helper()
	data, err := os.ReadFile("../../../../docs/vectors/owner-act-delivery-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		DeliveryCases []humanRoleDeliveryCase `json:"delivery_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	var accepted []humanRoleDeliveryCase
	for _, tc := range vectors.DeliveryCases {
		if tc.Result.Status == 200 && strings.HasPrefix(tc.Act.Act, "human-") {
			accepted = append(accepted, tc)
		}
	}
	if len(accepted) < 3 {
		t.Fatalf("only %d accepted human-role cases", len(accepted))
	}
	return accepted
}

func (tc humanRoleDeliveryCase) request(t *testing.T) humanRoleActRequest {
	t.Helper()
	r := humanRoleActRequest{
		Act: tc.Act.Act, AppID: tc.App.AppID, Origin: tc.App.OwnerActsOrigin, Role: tc.App.Role,
		InstallationID: tc.Act.Subject["installation_id"].(string), Principal: tc.Act.Subject["principal"].(string),
	}
	if raw, ok := tc.Body["credential"]; ok {
		data, _ := json.Marshal(raw)
		r.Credential = &awid.HumanCredential{}
		if err := json.Unmarshal(data, r.Credential); err != nil {
			t.Fatal(err)
		}
	}
	if contact, ok := tc.Body["notice_contact"].(string); ok {
		r.NoticeContact = contact
	}
	if certificate, ok := tc.Body["certificate"].(string); ok {
		r.Certificate = certificate
	}
	return r
}

func TestTheSubjectIsTheOneTheRouteExpects(t *testing.T) {
	for _, tc := range acceptedHumanRoleCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			subject, err := tc.request(t).subject()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(subject, tc.ExpectedSubject) {
				t.Fatalf("subject %v\nwant %v", subject, tc.ExpectedSubject)
			}
		})
	}
}

func TestTheDeliveryBodyIsTheOneTheRouteAccepts(t *testing.T) {
	for _, tc := range acceptedHumanRoleCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			signing, err := base64.StdEncoding.DecodeString(tc.Body["signing"].(string))
			if err != nil {
				t.Fatal(err)
			}
			body := tc.request(t).deliveryBody(signing, tc.Body["signature"].(string))
			var got map[string]any
			data, _ := json.Marshal(body)
			_ = json.Unmarshal(data, &got)
			if !reflect.DeepEqual(got, tc.Body) {
				t.Fatalf("body %v\nwant %v", got, tc.Body)
			}
		})
	}
}

func TestAnActTheRoleDoesNotDeclareIsRefusedBeforeSigning(t *testing.T) {
	tc := acceptedHumanRoleCases(t)[0]
	r := tc.request(t)
	r.Role.Acts = []string{"human-role.revoke"}
	if r.Act == "human-role.revoke" {
		r.Role.Acts = []string{"human-role.designate"}
	}
	if err := r.check(); errorCodeOf(err) != "act_not_declared" {
		t.Fatalf("err %v", err)
	}
}

func TestANoticeContactIsGivenExactlyWhenTheRoleDeclaresOne(t *testing.T) {
	for _, tc := range acceptedHumanRoleCases(t) {
		if tc.Act.Act == "human-role.revoke" {
			continue
		}
		r := tc.request(t)
		if r.NoticeContact == "" {
			r.NoticeContact = "someone@example.com"
		} else {
			r.NoticeContact = ""
		}
		if err := r.check(); errorCodeOf(err) != "notice_contact_mismatch" {
			t.Fatalf("%s: err %v", tc.Name, err)
		}
	}
}

func TestACredentialForAnotherHostIsRefusedBeforeSigning(t *testing.T) {
	for _, tc := range acceptedHumanRoleCases(t) {
		if tc.Act.Act == "human-role.revoke" {
			continue
		}
		r := tc.request(t)
		r.Credential.RPID = "api.example.com"
		if err := r.check(); errorCodeOf(err) != "credential_rp_id_mismatch" {
			t.Fatalf("%s: err %v", tc.Name, err)
		}
	}
}

func TestARevokeCarriesNoCredentialOrCertificate(t *testing.T) {
	for _, tc := range acceptedHumanRoleCases(t) {
		if tc.Act.Act != "human-role.revoke" {
			continue
		}
		r := tc.request(t)
		r.Credential = &awid.HumanCredential{CredentialID: "AAAA", PublicKey: "AAAA", RPID: "x"}
		if err := r.check(); errorCodeOf(err) != "credential_not_allowed" {
			t.Fatalf("%s: err %v", tc.Name, err)
		}
	}
}

func TestEveryAcceptedBrowserPasskeyRequestPassesTheChecks(t *testing.T) {
	checked := 0
	for _, tc := range acceptedHumanRoleCases(t) {
		r := tc.request(t)
		if r.Credential != nil && r.Credential.RPID == "aweb:" {
			continue
		}
		if err := r.check(); err != nil {
			t.Fatalf("%s: %v", tc.Name, err)
		}
		checked++
	}
	if checked < 5 {
		t.Fatalf("checked %d cases", checked)
	}
}

// The terminal security key is a separate, optional profile that this client
// does not implement, so it never signs a binding for an aweb: credential.
func TestASecurityKeyCredentialIsNotSigned(t *testing.T) {
	for _, tc := range acceptedHumanRoleCases(t) {
		r := tc.request(t)
		if r.Credential == nil || r.Credential.RPID != "aweb:" {
			continue
		}
		if err := r.check(); errorCodeOf(err) != "security_key_unsupported" {
			t.Fatalf("%s: err %v", tc.Name, err)
		}
		return
	}
	t.Fatal("no security key case")
}
