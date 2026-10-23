package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOriginOnlyConsentCannotAuthorizeDefaultMint(t *testing.T) {
	home := t.TempDir()
	original := []byte(`{"version":1,"apps":{"folio":"https://folio.example"}}`)
	if err := os.WriteFile(appApprovalsPath(home), original, 0600); err != nil {
		t.Fatal(err)
	}
	apps, skipped, err := prepareGrantAppSnapshots(home, "dev:example.com", false, nil, nil)
	if err != nil || len(apps) != 0 || len(skipped) != 1 || skipped[0].Code != "app_installation_approval_required" {
		t.Fatalf("apps=%v skipped=%v err=%v", apps, skipped, err)
	}
	after, err := os.ReadFile(appApprovalsPath(home))
	if err != nil || string(after) != string(original) {
		t.Fatal("unbound consent was adopted or modified")
	}
}

func TestInstallationApprovalReplacementPreservesOtherTeam(t *testing.T) {
	home := t.TempDir()
	for _, approval := range []struct{ team, id, origin string }{{"a:example.com", "install-a", "https://a.example"}, {"b:example.com", "install-b", "https://b.example"}, {"a:example.com", "replacement-a", "https://a.example"}} {
		if err := changeAppApproval(home, "folio", approval.origin, approval.team, approval.id); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := loadAppApprovals(home)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Installations["a:example.com"]["folio"].InstallationID != "replacement-a" || catalog.Installations["b:example.com"]["folio"].InstallationID != "install-b" || catalog.Installations["b:example.com"]["folio"].Origin != "https://b.example" {
		t.Fatal("replacement changed another team's approval")
	}
}

func TestCustodyInstallationBindingSurvivesRepinAndRefusesReplacementReplay(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	sessionKey, err := awid.LoadSigningKey(awconfig.GrantHomeSigningKeyPath(f.grantHome))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.serviceID = "svc"
	req := &awid.AppRequestSignRequest{Version: 1, Operation: "sign_app_request", GrantID: appTestGrantID, TeamID: f.grant.TeamID, SubjectDIDAW: f.grant.Subject.DIDAW, SubjectDIDKey: f.residentDID, Audience: "local-resident-custody:svc", AppID: "testapp", Verb: "get-thing", Args: map[string]any{"thing_id": "t1"}}
	if err := awid.SignAppRequestCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.signAppRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	f.setInstallation("testapp", appInstallationReceipt{InstallationID: "fixture-testapp", Generation: 2, State: "active", OriginVerified: true})
	if _, err := f.svc.signAppRequest(context.Background(), req); err != nil {
		t.Fatalf("same-ID repin refused: %v", err)
	}
	for _, tc := range []struct{ id, state, code string }{{"fixture-testapp", "uninstalled", "app_installation_inactive"}, {"replacement", "active", "app_installation_changed"}} {
		f.setInstallation("testapp", appInstallationReceipt{InstallationID: tc.id, Generation: 3, State: tc.state, OriginVerified: true})
		_, err := f.svc.signAppRequest(context.Background(), req)
		var refusal *installationApprovalRefusal
		if !errors.As(err, &refusal) || refusal.Code != tc.code {
			t.Fatalf("cached replay after%s: %v", tc.state, err)
		}
	}
	// Missing identity never falls back to origin or manifest equality.
	snapshot, err := loadGrantAppToolsSnapshot(f.residentHome, appTestGrantID)
	if err != nil {
		t.Fatal(err)
	}
	app := snapshot.Apps["testapp"]
	app.InstallationID = ""
	snapshot.Apps["testapp"] = app
	path, _ := grantAppToolsPath(f.residentHome, appTestGrantID)
	raw, _ := json.Marshal(snapshot)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.signAppRequest(context.Background(), req)
	var refusal *installationApprovalRefusal
	if !errors.As(err, &refusal) || refusal.Code != "app_installation_required" {
		t.Fatalf("unbound snapshot authorized: %v", err)
	}
}

// Unit boundary proof; the disposable Folio stack separately exercises the real
// mint command after an admin's same-origin/digest uninstall/reinstall.
func TestGrantAppToolExplicitMintRequiresCurrentInstallationApproval(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	const appID = "testapp"
	selected, err := buildGrantAppSnapshots(map[string][]string{appID: {"get-thing"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	origin := selected[appID].App.Origin
	mint := func() error {
		apps, skipped, err := prepareGrantAppSnapshots(f.residentHome, f.grant.TeamID, true, []string{"testapp:get-thing"}, nil)
		if err != nil {
			return err
		}
		_, err = bindGrantInstallations(context.Background(), f.svc.clientDeps(context.Background()).client,
			f.grant.TeamID, f.residentHome, true, apps, skipped)
		return err
	}
	if err := changeAppApproval(f.residentHome, appID, origin, f.grant.TeamID, "fixture-testapp"); err != nil {
		t.Fatal(err)
	}
	if err := mint(); err != nil {
		t.Fatalf("approved original install: %v", err)
	}
	f.setInstallation(appID, appInstallationReceipt{InstallationID: "replacement", Generation: 3, State: "active", OriginVerified: true})
	err = mint()
	var refusal *installationApprovalRefusal
	if !errors.As(err, &refusal) || refusal.Code != "app_installation_changed" {
		t.Fatalf("explicit mint adopted the replacement: %v", err)
	}
	if err := changeAppApproval(f.residentHome, appID, "", "", ""); err != nil {
		t.Fatal(err)
	}
	err = mint()
	if !errors.As(err, &refusal) || refusal.Code != "app_installation_approval_required" {
		t.Fatalf("explicit mint authorized without approval: %v", err)
	}
	if err := changeAppApproval(f.residentHome, appID, origin, f.grant.TeamID, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := mint(); err != nil {
		t.Fatalf("fresh explicit approval: %v", err)
	}
}
