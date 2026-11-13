package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"os"
	"testing"
)

func appliedTestResult(id string, signing, signature []byte) map[string]any {
	digest, _ := awid.ProtectedArtifactDigest(signing, base64.RawStdEncoding.EncodeToString(signature))
	return map[string]any{"v": 2, "type": "aweb.protected-delivery", "artifact": map[string]any{"signing": base64.StdEncoding.EncodeToString(signing), "signature": base64.StdEncoding.EncodeToString(signature)}, "delivery": map[string]any{"mode": "service_owned", "state": "applied", "reference": map[string]any{"operation_id": id, "artifact_sha256": digest}}}
}
func TestAdmissionAndRemovalAcceptConfirmedServiceDelivery(t *testing.T) {
	t.Run("admission", func(t *testing.T) {
		_, p, s := admitTestSetup(t)
		s.serviceOwned = true
		if _, e := admitMember(context.Background(), s.options(), p, admitTestRequest(t)); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("removal", func(t *testing.T) {
		key, p, s := removeTestSetup(t)
		s.serviceOwned = true
		if _, e := removeMember(context.Background(), s.options(), p, removeTestRequest(removeTestCertificate(t, key, ""))); e != nil {
			t.Fatal(e)
		}
	})
}
func TestRetainedDeliveryResultRefusesAnotherReferenceOrMode(t *testing.T) {
	for _, change := range []string{"operation", "digest", "mode", "pending", "extra", "version"} {
		t.Run(change, func(t *testing.T) {
			f := appliedTestResult(admitTestOperation, []byte("artifact"), make([]byte, 64))
			d := f["delivery"].(map[string]any)
			ref := d["reference"].(map[string]any)
			switch change {
			case "operation":
				ref["operation_id"] = removeTestOperation
			case "digest":
				ref["artifact_sha256"] = "sha256:wrong"
			case "mode":
				d["mode"] = "local"
			case "pending":
				d["state"] = "pending"
			case "extra":
				f["headers"] = map[string]any{}
			case "version":
				f["v"] = 3
			}
			raw, _ := json.Marshal(f)
			if _, _, reason := retainedSignedResult(raw, &handoff.Prepared{OperationID: admitTestOperation}); reason == "" {
				t.Fatal("accepted changed receipt")
			}
		})
	}
}

// A resumed expired operation may recover history; no execute or app POST is
// authorized by that read. Unconfirmed and mismatched results stay unusable.
func TestExpiredServiceOwnedAdmissionRecoversOnlyExactAppliedHistory(t *testing.T) {
	for _, scenario := range []string{"applied", "unresolved", "wrong-reference"} {
		t.Run(scenario, func(t *testing.T) {
			_, profile, service := admitTestSetup(t)
			request := admitTestRequest(t)
			binding, _ := admissionBinding(profile, request.Team)
			if _, err := operationBytes(profile, request.OperationID, admissionBody(profile, binding, request)); err != nil {
				t.Fatal(err)
			}
			service.serviceOwned = true
			service.expired = true
			service.sent = admissionBody(profile, binding, request)
			service.prepared()
			service.receipt = string(service.committed())
			if scenario == "unresolved" {
				service.receipt = `{"state":"unknown","code":"external_effect_unresolved"}`
			}
			if scenario == "wrong-reference" {
				var reply map[string]any
				_ = json.Unmarshal([]byte(service.receipt), &reply)
				reply["result"].(map[string]any)["delivery"].(map[string]any)["reference"].(map[string]any)["artifact_sha256"] = "b"
				raw, _ := json.Marshal(reply)
				service.receipt = string(raw)
			}
			_, err := admitMember(context.Background(), service.options(), profile, request)
			if service.executes != 0 || service.reads != 1 {
				t.Fatalf("executes=%d reads=%d", service.executes, service.reads)
			}
			if scenario == "applied" {
				if err != nil {
					t.Fatal(err)
				}
				if _, e := os.Stat(request.CertificateOut); e != nil {
					t.Fatal(e)
				}
			} else {
				if err == nil {
					t.Fatal("accepted unresolved or mismatched receipt")
				}
				if _, e := os.Stat(request.CertificateOut); !os.IsNotExist(e) {
					t.Fatal("released a certificate")
				}
				if saved, _ := awconfig.LoadPendingGovernanceOperation(request.OperationID); saved == nil {
					t.Fatal("forgot unresolved operation")
				}
			}
		})
	}
}
