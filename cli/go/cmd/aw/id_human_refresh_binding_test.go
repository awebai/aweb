package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awconfig"
)

func refreshBindingFixture(t *testing.T) (*humanParticipation, map[string]any) {
	t.Helper()
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/awebai/approval-service").Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), "vectors", "binding-refresh-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := proof.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cases, ok := corpus["cases"].([]any)
	if !ok || len(cases) == 0 {
		t.Fatal("shared refresh cases missing")
	}
	first, ok := cases[0].(map[string]any)
	if !ok {
		t.Fatal("invalid shared case")
	}
	binding, ok := first["binding"].(map[string]any)
	if !ok {
		t.Fatal("shared binding missing")
	}
	b, ok := binding["binding"].(map[string]any)
	if !ok {
		t.Fatal("shared binding body missing")
	}
	person, ok := b["person"].(string)
	if !ok {
		t.Fatal("shared person missing")
	}
	key, ok := b["identity_key"].(string)
	if !ok {
		t.Fatal("shared key missing")
	}
	domain, ok := b["organisation"].(string)
	if !ok {
		t.Fatal("shared organisation missing")
	}
	return &humanParticipation{dir: t.TempDir(), record: &awconfig.HumanRecord{StableID: person, DIDKey: key, Domain: domain}}, binding
}

func refreshPacketFixture(t *testing.T, h *humanParticipation, binding map[string]any) []byte {
	t.Helper()
	previous, err := proof.Commitment("binding_commitment", binding)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proof.Canonical(map[string]any{"version": 1, "requester": map[string]any{"kind": "identity", "id": h.record.StableID, "key": h.record.DIDKey}, "previous_binding_commitment": previous, "binding": binding, "id_chain": []any{map[string]any{"fixture": "carrier-chain"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHumanBindingRefreshPreservesHistoricalEvidence(t *testing.T) {
	h, binding := refreshBindingFixture(t)
	historical := []string{"approval-binding.json", "approval-evidence.json", "enrollment-session.json"}
	for _, name := range historical {
		if err := os.WriteFile(filepath.Join(h.dir, name), []byte("original historical bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	packet, err := readHumanBindingRefreshPacket(refreshPacketFixture(t, h, binding), humanBindingRefreshInput{Human: h, Current: binding})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := proof.Commitment("binding_commitment", binding)
	if err != nil {
		t.Fatal(err)
	}
	answer := map[string]any{"version": json.Number("1"), "person": h.record.StableID, "state": "active", "binding_commitment": commitment}
	if err := saveCheckedHumanBindingRefresh(h, packet, humanBindingRefreshAnswer{Status: 200, Body: answer}); err != nil {
		t.Fatal(err)
	}
	for _, name := range historical {
		raw, err := os.ReadFile(filepath.Join(h.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != "original historical bytes\n" {
			t.Fatalf("rewrote %s", name)
		}
	}
	loaded, err := loadHumanApprovalBinding(h.dir)
	if err != nil || !sameEnrollmentValue(loaded, binding) {
		t.Fatalf("live binding not saved: %v", err)
	}
	mode, err := os.Stat(filepath.Join(h.dir, "approval-live-binding.json"))
	if err != nil || mode.Mode().Perm() != 0600 {
		t.Fatalf("live binding permissions: %v", err)
	}
}

func TestHumanBindingRefreshRefusesUnboundAnswersAndRetainsLiveBinding(t *testing.T) {
	for _, failure := range []string{"wrong commitment", "service refusal"} {
		t.Run(failure, func(t *testing.T) {
			h, binding := refreshBindingFixture(t)
			if err := saveHumanEnrollment(filepath.Join(h.dir, "approval-live-binding.json"), binding); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(h.dir, "approval-live-binding.json"))
			if err != nil {
				t.Fatal(err)
			}
			packet, err := readHumanBindingRefreshPacket(refreshPacketFixture(t, h, binding), humanBindingRefreshInput{Human: h, Current: binding})
			if err != nil {
				t.Fatal(err)
			}
			answer := humanBindingRefreshAnswer{Status: 200, Body: map[string]any{"version": json.Number("1"), "person": h.record.StableID, "state": "active", "binding_commitment": "sha256:" + strings.Repeat("0", 64)}}
			want := "The service did not confirm this binding."
			if failure == "service refusal" {
				answer = humanBindingRefreshAnswer{Status: 409, Body: map[string]any{"version": json.Number("1"), "error": map[string]any{"code": "binding_refresh_previous_changed", "message": "Use the last successful live binding and retry refresh."}}}
				want = "Use the last successful live binding and retry refresh."
			}
			err = saveCheckedHumanBindingRefresh(h, packet, answer)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("missing actionable refusal: %v", err)
			}
			after, err := os.ReadFile(filepath.Join(h.dir, "approval-live-binding.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("unconfirmed answer replaced live binding")
			}
		})
	}
}

func TestHumanBindingRefreshPacketKeepsTheSelectedPersonAndService(t *testing.T) {
	for _, field := range []string{"requester", "previous_binding_commitment", "binding"} {
		t.Run(field, func(t *testing.T) {
			h, binding := refreshBindingFixture(t)
			packet, err := proof.Parse(refreshPacketFixture(t, h, binding))
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "requester":
				packet[field] = map[string]any{"kind": "namespace_controller", "namespace": h.record.Domain, "key": h.record.DIDKey}
			case "previous_binding_commitment":
				packet[field] = "sha256:" + strings.Repeat("0", 64)
			case "binding":
				raw, err := proof.Canonical(binding)
				if err != nil {
					t.Fatal(err)
				}
				changed, err := proof.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				body, ok := changed["binding"].(map[string]any)
				if !ok {
					t.Fatal("binding body missing")
				}
				body["origin"] = "https://another.example"
				packet[field] = changed
			}
			raw, err := proof.Canonical(packet)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readHumanBindingRefreshPacket(raw, humanBindingRefreshInput{Human: h, Current: binding}); err == nil {
				t.Fatal("accepted another person, generation or service")
			}
		})
	}
}
