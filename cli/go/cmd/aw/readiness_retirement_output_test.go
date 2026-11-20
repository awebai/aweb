package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
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

func TestInitOutcomeReturnsClosedOutputAfterConnecting(t *testing.T) {
	previousJSON := jsonFlag
	t.Cleanup(func() { jsonFlag = previousJSON })
	for _, json := range []bool{true, false} {
		jsonFlag = json
		root := t.TempDir()
		result := &initResult{ServerName: "local", Path: initPathReconnect}
		err := invokeWithCommandStdout(t, closedCommandStdout(t), func() error {
			return printInitOutcome(connectOutput{Status: "connected", TeamID: "one:example.test", Alias: "member"}, result, root, initDefaultSetup(result, root))
		})
		if !errors.Is(err, os.ErrClosed) || !strings.HasSuffix(err.Error(), "Check the output destination and inspect the connected identity before retrying init.") {
			t.Fatalf("init JSON=%t lost its output failure and recovery: %v", json, err)
		}
	}
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
				if verdict.Home != wakeStatusHome || verdict.Ready || verdict.Code != wake.ReadinessDaemonNotRunning {
					t.Fatalf("proved absence changed: %s", raw)
				}
			}
		})
	}
}

func TestOATSRealLocalRetirementReturnsClosedOutputAndKeepsItsReceiptOutcome(t *testing.T) {
	for _, revoked := range []bool{true, false} {
		name := "revocation pending"
		if revoked {
			name = "already revoked"
		}
		t.Run(name, func(t *testing.T) {
			world := newRealCommandWorld(t)
			member := world.addLocalMember(t, "worker")
			t.Setenv("HOME", world.UserHome)
			t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
			t.Setenv("AWEB_IDENTITY_HOME", "")
			key := world.TeamKey
			if !revoked {
				_, wrongKey, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				key = wrongKey
			}
			if err := awconfig.SaveTeamKey(world.Domain, "backend", key); err != nil {
				t.Fatal(err)
			}
			var binding identityStatusOutput
			if err := json.Unmarshal([]byte(world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)), &binding); err != nil {
				t.Fatal(err)
			}
			workspaceID := binding.WorkspaceID
			initial, initialErr := world.runInIdentityHome(member.Home, "workspace", "delete", workspaceID)
			if (initialErr == nil) != revoked {
				t.Fatalf("real retirement did not produce the selected outcome: %v / %s", initialErr, initial)
			}
			var initialOutput workspaceDeleteOutput
			if err := json.Unmarshal([]byte(initial), &initialOutput); err != nil || initialOutput.ReceiptPath == "" || initialOutput.AliasReleased != revoked {
				t.Fatalf("real retirement did not produce its receipt: %v / %s", err, initial)
			}
			path := initialOutput.ReceiptPath
			t.Chdir(filepath.Dir(member.Home))
			previousHome, previousActive, previousTeam, previousJSON := identityHomeFlag, activeIdentityHome, teamFlag, jsonFlag
			identityHomeFlag, activeIdentityHome, teamFlag, jsonFlag = "", awconfig.IdentityHome{}, "", true
			t.Cleanup(func() {
				identityHomeFlag, activeIdentityHome, teamFlag, jsonFlag = previousHome, previousActive, previousTeam, previousJSON
			})
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
				if errorCodeOf(closedErr) != string(retiredRevocationPending) || !strings.Contains(closedErr.Error(), "receipt retained at "+path+"; retry aw workspace delete "+workspaceID) {
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
