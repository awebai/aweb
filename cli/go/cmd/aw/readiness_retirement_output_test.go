package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/wake"
)

func invokeWithCommandStdout(t *testing.T, file *os.File, run func() error) error {
	t.Helper()
	previous, written := os.Stdout, commandStdout.written
	os.Stdout = file
	defer func() { os.Stdout, commandStdout.written = previous, written }()
	return run()
}

func closedCommandStdout(t *testing.T) *os.File {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "closed-output"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestWakeReadinessReturnsClosedOutputAndKeepsItsDiagnosticJSON(t *testing.T) {
	for _, selected := range []string{"all homes", "one home"} {
		t.Run(selected, func(t *testing.T) {
			t.Setenv("AW_WAKE_STATE_DIR", t.TempDir())
			previousHome, previousMinimum, previousState, previousJSON := wakeStatusHome, wakeStatusMinVersion, wakeStateDirFlag, jsonFlag
			wakeStatusHome, wakeStatusMinVersion, wakeStateDirFlag, jsonFlag = "", "", "", true
			if selected == "one home" {
				wakeStatusHome = t.TempDir()
			}
			t.Cleanup(func() {
				wakeStatusHome, wakeStatusMinVersion, wakeStateDirFlag, jsonFlag = previousHome, previousMinimum, previousState, previousJSON
			})
			run := func() error { return runWakeStatus(wakeStatusCmd, nil) }
			if err := invokeWithCommandStdout(t, closedCommandStdout(t), run); !errors.Is(err, os.ErrClosed) || !strings.HasSuffix(err.Error(), "Check the output destination, then rerun aw wake status.") {
				t.Fatalf("readiness reported success with a closed output: %v", err)
			}
			path := filepath.Join(t.TempDir(), "status.json")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			runErr := invokeWithCommandStdout(t, file, run)
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if runErr != nil {
				t.Fatalf("readiness diagnostic changed its normal result: %v", runErr)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Readiness    json.RawMessage `json:"readiness"`
				ControlError string          `json:"control_error"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.ControlError == "" {
				t.Fatal("lost the actual missing-control diagnostic")
			}
			if wakeStatusHome == "" {
				if string(out.Readiness) != "[]" {
					t.Fatalf("empty home list changed: %s", raw)
				}
			} else {
				var verdict wake.ReadinessVerdict
				if err := json.Unmarshal(out.Readiness, &verdict); err != nil {
					t.Fatal(err)
				}
				if verdict.Home != wakeStatusHome || verdict.Ready || verdict.Code != wake.ReadinessDaemonUnavailable {
					t.Fatalf("unavailable control became ready: %s", raw)
				}
			}
		})
	}
}

func TestLocalRetirementReturnsClosedOutputAndKeepsItsReceiptOutcome(t *testing.T) {
	for _, revoked := range []bool{true, false} {
		name := "revocation pending"
		if revoked {
			name = "already revoked"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AWEB_IDENTITY_HOME", "")
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			registryURL := "http://" + listener.Addr().String()
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("AWID_REGISTRY_URL", registryURL)
			root := t.TempDir()
			previousDir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(root); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chdir(previousDir); err != nil {
					t.Error(err)
				}
			})
			previousHome, previousTeam, previousJSON := identityHomeFlag, teamFlag, jsonFlag
			identityHomeFlag, teamFlag, jsonFlag = "", "", true
			t.Cleanup(func() { identityHomeFlag, teamFlag, jsonFlag = previousHome, previousTeam, previousJSON })
			output, certificate := writeSelfCustodyIdentityForTest(t, root, "one:example.test")
			state := teamStateBinding(certificate.Team, certificate.Alias)
			if err := awconfig.SaveTeamState(root, &state); err != nil {
				t.Fatal(err)
			}
			workspaceID := "11111111-1111-4111-8111-111111111111"
			binding := workspaceBinding("https://service.example.test", certificate.Team, output.Alias, workspaceID)
			if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(root, ".aw", "workspace.yaml"), &binding); err != nil {
				t.Fatal(err)
			}
			path, err := localRetirementReceiptPath(awconfig.IdentityHome{Root: filepath.Join(root, ".aw")}, workspaceID)
			if err != nil {
				t.Fatal(err)
			}
			receipt := localRetirementReceipt{Version: localRetirementReceiptVersion, TeamID: certificate.Team, CertificateID: certificate.CertificateID, MemberDIDKey: certificate.MemberDIDKey, RegistryURL: registryURL, Revoked: revoked, Delete: workspaceDeleteOutput{WorkspaceID: workspaceID, Alias: certificate.Alias, IdentityDeleted: true}}
			if err := saveLocalRetirementReceipt(path, receipt); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			run := func() error { return runWorkspaceDelete(workspaceDeleteCmd, []string{workspaceID}) }
			closedErr := invokeWithCommandStdout(t, closedCommandStdout(t), run)
			if !errors.Is(closedErr, os.ErrClosed) || !strings.HasSuffix(closedErr.Error(), "Check the output destination and retain this identity home; follow any retirement recovery instructions before retrying.") {
				t.Fatalf("retirement lost the output failure: %v", closedErr)
			}
			if !revoked {
				var transport *net.OpError
				if errorCodeOf(closedErr) != string(retiredRevocationPending) || !errors.As(closedErr, &transport) || !strings.Contains(closedErr.Error(), "receipt retained at "+path+"; retry aw workspace delete "+workspaceID) {
					t.Fatalf("output failure replaced pending revocation or its recovery: %v", closedErr)
				}
			}
			pathOut := filepath.Join(t.TempDir(), "retirement.json")
			file, err := os.Create(pathOut)
			if err != nil {
				t.Fatal(err)
			}
			runErr := invokeWithCommandStdout(t, file, run)
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if revoked && runErr != nil {
				t.Fatalf("cached completed retirement changed: %v", runErr)
			}
			if !revoked && errorCodeOf(runErr) != string(retiredRevocationPending) {
				t.Fatalf("pending retirement changed: %v", runErr)
			}
			raw, err := os.ReadFile(pathOut)
			if err != nil {
				t.Fatal(err)
			}
			var result workspaceDeleteOutput
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			want := retiredRevocationPending
			if revoked {
				want = retiredAndRevoked
			}
			if result.WorkspaceID != workspaceID || result.RetirementCode != want || result.AliasReleased != revoked {
				t.Fatalf("retirement outcome changed: %s", raw)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("presentation failure changed the retained retirement receipt")
			}
		})
	}
}
