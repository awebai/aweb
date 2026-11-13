package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

func protectedLogFixture(t *testing.T) (*awid.LogKeyRecord, string, json.RawMessage) {
	t.Helper()
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord("engineering:customer.example", pair.Public, time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signed := *rec
	if err := awid.SignLogKeyRecord(&signed, key); err != nil {
		t.Fatal(err)
	}
	signing, err := awid.LogKeyRecordSigningBytes(&signed)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.RawStdEncoding.DecodeString(signed.Signature)
	result, _ := json.Marshal(map[string]string{"signing": base64.StdEncoding.EncodeToString(signing), "signature": base64.StdEncoding.EncodeToString(sig)})
	return rec, signed.TeamKeyDID, result
}

func TestProtectedLogReceiptUsesTheSharedBytesAndAttachesItsSignature(t *testing.T) {
	rec, did, result := protectedLogFixture(t)
	signed, err := protectedLogRecord(rec, did, result)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Signature != "" || rec.TeamKeyDID != "" {
		t.Fatal("input changed")
	}
	if err := awid.VerifyLogKeyRecord(signed, rec.TeamID, did); err != nil {
		t.Fatal(err)
	}
	if len(signed.Signature) != 86 {
		t.Fatal("not canonical signature")
	}
	for _, name := range []string{"other key", "other record", "extra result", "duplicate result", "short signature", "raw signature"} {
		t.Run(name, func(t *testing.T) {
			candidate := *rec
			key := did
			raw := append([]byte(nil), result...)
			fields := map[string]string{}
			_ = json.Unmarshal(result, &fields)
			switch name {
			case "other key":
				_, key, _ = protectedLogFixture(t)
			case "other record":
				candidate.CreatedAt = "2026-11-12T00:00:01Z"
			case "extra result":
				fields["private_key"] = "no"
				raw, _ = json.Marshal(fields)
			case "duplicate result":
				raw = append(raw[:len(raw)-1], []byte(`,"signature":"AAAA"}`)...)
			case "short signature":
				fields["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 63))
				raw, _ = json.Marshal(fields)
			case "raw signature":
				b, _ := base64.StdEncoding.DecodeString(fields["signature"])
				fields["signature"] = base64.RawStdEncoding.EncodeToString(b)
				raw, _ = json.Marshal(fields)
			}
			if _, err := protectedLogRecord(&candidate, key, raw); err == nil {
				t.Fatal("wrong receipt accepted")
			}
		})
	}
}

func TestProtectedLogIntentRefusesAnUnboundOrMalformedRecord(t *testing.T) {
	rec, did, _ := protectedLogFixture(t)
	profile, _ := vectorProfile(t)
	binding := profile.Bindings[0]
	binding.AuthorityKeyDID = did
	intent, err := protectedLogIntent(profile, &binding, rec)
	if err != nil {
		t.Fatal(err)
	}
	if intent["operation"] != "team.log-key.sign" || intent["audience"] != profile.RequestOrigin {
		t.Fatal(intent)
	}
	for _, mutate := range []func(*awid.LogKeyRecord){
		func(r *awid.LogKeyRecord) { r.TeamID = "another:customer.example" },
		func(r *awid.LogKeyRecord) { r.V = 2 },
		func(r *awid.LogKeyRecord) { r.CreatedAt = "2026-11-12T00:00:00+00:00" },
		func(r *awid.LogKeyRecord) { r.KeyID = "sha256:wrong" },
	} {
		r := *rec
		mutate(&r)
		if _, err := protectedLogIntent(profile, &binding, &r); err == nil {
			t.Fatal("bad record accepted")
		}
	}
}

func TestProtectedLogMaterializationRetainsStateUntilOutputSucceeds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rec, did, result := protectedLogFixture(t)
	const id = "11111111-1111-4111-8111-111111111111"
	saved := &awconfig.PendingGovernanceOperation{OperationID: id, RequestOrigin: "https://request.example", HumanOrigin: "https://human.example", Body: []byte(`{}`)}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	receipt := &handoff.Receipt{OperationID: id, State: "committed", Result: result}
	if err := settleProtectedLog(cmd, id, rec, did, receipt, nil, filepath.Join(t.TempDir(), "absent", "record.json")); err == nil {
		t.Fatal("bad output succeeded")
	}
	if state, _ := awconfig.LoadPendingGovernanceOperation(id); state == nil {
		t.Fatal("forgot before write")
	}
	out := filepath.Join(t.TempDir(), "record.json")
	if err := settleProtectedLog(cmd, id, rec, did, receipt, nil, out); err != nil {
		t.Fatal(err)
	}
	if state, _ := awconfig.LoadPendingGovernanceOperation(id); state != nil {
		t.Fatal("not forgotten after write")
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var signed awid.LogKeyRecord
	if err = json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	if err := awid.VerifyLogKeyRecord(&signed, rec.TeamID, did); err != nil {
		t.Fatal(err)
	}
}
