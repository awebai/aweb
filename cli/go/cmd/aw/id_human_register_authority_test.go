package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// Root authority is checked through real DNS/status boundaries before the
// person's real key signs even the first registration request.
func TestHumanRegisterChecksCurrentIssuerBeforePersonSigns(t *testing.T) {
	for _, scenario := range []string{"current root", "current root pending human", "replaced root", "unavailable evidence"} {
		t.Run(scenario, func(t *testing.T) {
			v := loadWhoVectors(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("APP_ENV", "development")
			status := v.Statuses["normal"]
			if scenario == "current root pending human" {
				status = v.Statuses["human-not-registered"]
			}
			if scenario == "replaced root" {
				status = v.Statuses["root-replaced"]
			}
			writes, prompts := 0, 0
			registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/id-certificates/status" {
					if scenario == "unavailable evidence" {
						http.Error(w, "unavailable", 503)
						return
					}
					json.NewEncoder(w).Encode(status)
					return
				}
				if r.Method == http.MethodPost {
					writes++
					http.Error(w, "registration stopped at external boundary", 503)
					return
				}
				t.Errorf("unexpected read %s", r.URL.Path)
				http.NotFound(w, r)
			}))
			origin := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
			t.Setenv("AWID_REGISTRY_URL", origin)
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, origin))
			seed, _ := hex.DecodeString(v.Keys["alice"].SeedHex)
			key := ed25519.NewKeyFromSeed(seed)
			record := &awconfig.HumanRecord{StableID: v.Keys["alice"].DIDAW, DIDKey: v.Keys["alice"].DIDKey, Domain: "example.com", State: awconfig.HumanPrepared, RegistryURL: origin}
			human := &humanParticipation{record: record, dir: t.TempDir(), output: os.Stderr, sign: func(payload []byte, description string) (string, []byte, error) {
				prompts++
				return record.DIDKey, ed25519.Sign(key, payload), nil
			}}
			chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed}}
			_, err := registerHumanChain(context.Background(), human, chain, origin)
			if err == nil {
				t.Fatal("fixture registration boundary should stop the command")
			}
			if strings.HasPrefix(scenario, "current root") {
				if prompts == 0 || writes == 0 {
					t.Fatalf("valid root did not reach registration: prompts=%d writes=%d err=%v", prompts, writes, err)
				}
			} else if prompts != 0 || writes != 0 {
				t.Fatalf("untrusted issuer reached person signing: prompts=%d writes=%d err=%v", prompts, writes, err)
			}
		})
	}
}

func TestHumanRegisterRefusesChainWithoutCertificates(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	v := loadWhoVectors(t)
	registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("malformed chain reached registry: %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", 500)
	}))
	origin := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
	t.Setenv("AWID_REGISTRY_URL", origin)
	serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, origin))
	human := &humanParticipation{record: &awconfig.HumanRecord{StableID: v.Keys["alice"].DIDAW, DIDKey: v.Keys["alice"].DIDKey, Domain: "example.com", RegistryURL: origin, State: awconfig.HumanPrepared}}
	_, err := registerHumanChain(context.Background(), human, map[string]any{"v": 1, "type": "aweb.id-chain"}, origin)
	if err == nil || err.Error() != "issued human certificate is malformed" {
		t.Fatalf("malformed chain error=%v", err)
	}
}
