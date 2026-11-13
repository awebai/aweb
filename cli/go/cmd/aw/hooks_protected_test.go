package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

func TestProtectedHookDeliveryKeepsTheExactActUntilItsEffectIsAcknowledged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	row := hookTestRegistration()
	subject, err := hookBindingRowSubject(row)
	if err != nil {
		t.Fatal(err)
	}
	fields, key := signableAct(t, "hook-binding.activate", subject)
	calls := 0
	mode := "refuse"
	effects := 0
	var first []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		calls++
		if r.URL.Path != "/v1/apps/hook-bindings/"+row.BindingID+"/activate" {
			t.Errorf("wrong route %s", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body["act"])
		if first == nil {
			first = raw
		} else if !bytes.Equal(first, raw) {
			t.Error("signed act changed")
		}
		if _, err := awid.VerifyOwnerAct(raw, body["signature"], awid.OwnerActVerifyOptions{TeamID: row.TeamID, CurrentTeamKeyDID: fields["team_key_did"].(string), Audience: fields["aud"].(string), Acts: awid.CoreOwnerActs, ExpectedSubject: subject, Now: time.Now(), NonceUsed: func(string) bool { return false }}); err != nil {
			t.Error(err)
		}
		if mode == "refuse" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"detail":"owner_required"}`))
			return
		}
		if effects == 0 {
			effects++
		}
		if mode == "drop" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		active := row
		active.State = "active"
		_ = json.NewEncoder(w).Encode(active)
	}))
	defer server.Close()
	fields["aud"] = server.URL
	signing, sig, err := awid.SignOwnerAct(key, fields)
	if err != nil {
		t.Fatal(err)
	}
	rawSig, _ := base64.RawStdEncoding.DecodeString(sig)
	result, _ := json.Marshal(map[string]string{"signing": base64.StdEncoding.EncodeToString(signing), "signature": base64.StdEncoding.EncodeToString(rawSig)})
	profile, _ := vectorProfile(t)
	binding := profile.Bindings[0]
	binding.Scope["authority"].(map[string]any)["id"] = row.TeamID
	binding.AuthorityKeyDID = fields["team_key_did"].(string)
	intent := protectedRoleIntent("hook-binding.activate", binding.Scope, server.URL, subject)
	client, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetHTTPClient(server.Client())
	const id = "11111111-1111-4111-8111-111111111111"
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: id, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	receipt := &handoff.Receipt{OperationID: id, State: "committed", Result: result}
	if err := settleProtectedHook(cmd, client, id, intent, &binding, receipt, nil); err == nil {
		t.Fatal("failed delivery settled")
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(id); saved == nil {
		t.Fatal("forgot failed delivery")
	}
	mode = "drop"
	if err := settleProtectedHook(cmd, client, id, intent, &binding, receipt, nil); err == nil {
		t.Fatal("lost response settled")
	}
	if state, _ := awconfig.LoadPendingGovernanceOperation(id); state == nil {
		t.Fatal("forgot lost response")
	}
	mode = "ack"
	if err := settleProtectedHook(cmd, client, id, intent, &binding, receipt, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || effects != 1 {
		t.Fatalf("posts=%d", calls)
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(id); saved != nil {
		t.Fatal("did not forget applied")
	}
	receipt.Result = json.RawMessage(`{"signing":"bad","signature":"bad"}`)
	if err := settleProtectedHook(cmd, client, id, intent, &binding, receipt, nil); err == nil || calls != 3 {
		t.Fatal("invalid receipt delivered")
	}
}

func TestHookActivationHasOnlyTheProtectedOnlineRoute(t *testing.T) {
	cmd := hookOwnerActCmd("activate", "hook-binding.activate", "activate", "pinned manifest")
	if cmd.Flags().Lookup("protected-profile") == nil || cmd.Flags().Lookup("approver") == nil {
		t.Fatal("protected route absent")
	}
	if cmd.Flags().Lookup("yes") != nil {
		t.Fatal("local confirmation still signs activation")
	}
	if err := runProtectedHookActivate(cmd, "logs", "binding", "", ""); err == nil {
		t.Fatal("missing profile fell back")
	}
}
