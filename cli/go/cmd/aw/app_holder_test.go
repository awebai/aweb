package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installHolderTestApp installs, under a fresh AW_HOME, a version 3 manifest
// whose owner_acts is the delivery vector's first valid manifest case.
func installHolderTestApp(t *testing.T, name string, withOwnerActs bool) (origin, ownerOrigin string) {
	t.Helper()
	data, err := os.ReadFile("../../../../docs/vectors/owner-act-delivery-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ManifestCases []struct {
			AppOrigin string          `json:"app_origin"`
			OwnerActs json.RawMessage `json:"owner_acts"`
			Error     *string         `json:"error"`
		} `json:"manifest_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.ManifestCases {
		if tc.Error != nil {
			continue
		}
		doc := map[string]any{
			"manifest_version": 3,
			"app":              map[string]any{"id": name, "version": "1.0.0", "origin": tc.AppOrigin},
			"tools":            []any{},
		}
		var ownerActs struct {
			Origin string `json:"origin"`
		}
		_ = json.Unmarshal(tc.OwnerActs, &ownerActs)
		if withOwnerActs {
			doc["owner_acts"] = tc.OwnerActs
		} else {
			doc["manifest_version"] = 2
		}
		manifest, _ := json.Marshal(doc)
		home := t.TempDir()
		t.Setenv("AW_HOME", home)
		dir := filepath.Join(home, "plugins", name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
			t.Fatal(err)
		}
		provenance, _ := json.Marshal(pluginProvenance{AppName: name, AppID: name, Origin: tc.AppOrigin, Digest: "sha256:pinned"})
		if err := os.WriteFile(filepath.Join(dir, "provenance.json"), provenance, 0o600); err != nil {
			t.Fatal(err)
		}
		return tc.AppOrigin, ownerActs.Origin
	}
	t.Fatal("no valid manifest case")
	return "", ""
}

func TestAHolderAppResolvesBothPinnedOrigins(t *testing.T) {
	origin, ownerOrigin := installHolderTestApp(t, "example", true)
	app, err := installedHolderApp("example")
	if err != nil {
		t.Fatal(err)
	}
	if app.Origins.App != origin || app.Origins.Human != ownerOrigin || app.AppID != "example" || app.Digest != "sha256:pinned" {
		t.Fatalf("app %+v", app)
	}
	role := app.Resolved.OwnerActs.Roles[0]
	if got, err := app.role(role.Name); err != nil || got.Name != role.Name {
		t.Fatalf("role %+v err %v", got, err)
	}
}

func TestAHolderAppRefusesWhatItCannotAct(t *testing.T) {
	if _, err := installedHolderApp("missing"); errorCodeOf(err) != "app_not_installed" {
		t.Fatalf("missing: err %v", err)
	}
	installHolderTestApp(t, "plain", false)
	if _, err := installedHolderApp("plain"); errorCodeOf(err) != "owner_acts_undeclared" {
		t.Fatalf("plain: err %v", err)
	}
	installHolderTestApp(t, "example", true)
	app, err := installedHolderApp("example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.role("nobody.role"); errorCodeOf(err) != "role_not_declared" {
		t.Fatalf("role: err %v", err)
	}
}

func TestAHumanHolderUsesTheAppThisMachineInstalled(t *testing.T) {
	// The installed-app record is this machine's configuration (AW_HOME), not an
	// identity's: what an ordinary `aw plugin install` wrote is what a human
	// holder's `aw --human H app credential register` resolves. Installing is
	// not a human act, so --human stays refused for plugin install.
	origin, ownerOrigin := installHolderTestApp(t, "example", true)
	previousHuman, previousDomain := humanFlag, humanDomainFlag
	humanFlag, humanDomainFlag = "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn", "example.com"
	t.Cleanup(func() { humanFlag, humanDomainFlag = previousHuman, previousDomain })
	app, err := installedHolderApp("example")
	if err != nil || app.Origins.App != origin || app.Origins.Human != ownerOrigin || app.Digest != "sha256:pinned" {
		t.Fatalf("app %+v err %v", app, err)
	}
	if !humanParticipationAllowed(appCredentialRegisterCmd) || !humanParticipationAllowed(appRoleDesignateCmd) {
		t.Fatal("a human holder cannot register or be designated")
	}
	if humanParticipationAllowed(pluginInstallCmd) {
		t.Fatal("plugin install accepts --human")
	}
}

func TestAHumanOnlyMachineInstallsTheAppHostOnlyForItsHolder(t *testing.T) {
	// A machine with a human holder and no agent identity: a plain
	// `aw plugin install` (no --human) installs host-only, recording the
	// pinned manifest and its digest without registering anything, and the
	// human's credential register then resolves that app.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	data, err := os.ReadFile("../../../../docs/vectors/owner-act-delivery-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ManifestCases []struct {
			AppOrigin string          `json:"app_origin"`
			OwnerActs json.RawMessage `json:"owner_acts"`
			Error     *string         `json:"error"`
		} `json:"manifest_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	var manifest []byte
	var ownerOrigin string
	for _, tc := range vectors.ManifestCases {
		if tc.Error == nil {
			manifest, _ = json.Marshal(map[string]any{
				"manifest_version": 3, "owner_acts": tc.OwnerActs, "tools": []any{},
				"app": map[string]any{"id": "example", "version": "1.0.0", "origin": tc.AppOrigin},
			})
			var oa struct{ Origin string }
			_ = json.Unmarshal(tc.OwnerActs, &oa)
			ownerOrigin = oa.Origin
			break
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveNoManifestCatalog(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(manifest)
	}))
	defer server.Close()

	home := filepath.Join(tmp, "home")
	// Only a human holder is enrolled: its state is AWID state, not an aw identity home.
	if err := os.MkdirAll(filepath.Join(home, ".awid", "humans", "example.com"), 0o700); err != nil {
		t.Fatal(err)
	}
	install := exec.CommandContext(ctx, bin, "plugin", "install", server.URL, "--dev-origin", server.URL)
	install.Dir, install.Env = home, append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	out, err := install.CombinedOutput()
	if err != nil {
		t.Fatalf("host-only install: %v\n%s", err, out)
	}

	t.Setenv("AW_HOME", filepath.Join(home, ".aw"))
	previousHuman, previousDomain := humanFlag, humanDomainFlag
	humanFlag, humanDomainFlag = "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn", "example.com"
	t.Cleanup(func() { humanFlag, humanDomainFlag = previousHuman, previousDomain })
	app, err := installedHolderApp("example")
	if err != nil {
		t.Fatalf("the human holder cannot resolve the host-only install: %v\ninstall said: %s", err, out)
	}
	if app.Origins.App != server.URL || app.Origins.Human != ownerOrigin || !strings.HasPrefix(app.Digest, "sha256:") {
		t.Fatalf("app %+v", app)
	}
}
