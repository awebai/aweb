package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func TestHumanEnrollmentClientUsesFrozenAuthorizations(t *testing.T) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/awebai/approval-service").Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), "vectors", "requester-service-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []map[string]any `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range corpus.Cases {
		requester, _ := c["expected_requester"].(map[string]any)
		purpose, _ := c["purpose"].(string)
		if c["accept"] != true || requester["kind"] != "identity" || !strings.HasPrefix(purpose, "enrollment_") || c["test_signing_seed"] == nil {
			continue
		}
		count++
		t.Run(c["id"].(string), func(t *testing.T) {
			seed, err := base64.RawURLEncoding.DecodeString(c["test_signing_seed"].(string))
			if err != nil {
				t.Fatal(err)
			}
			private := ed25519.NewKeyFromSeed(seed)
			human := &humanParticipation{record: &awconfig.HumanRecord{StableID: requester["id"].(string), DIDKey: requester["key"].(string)}, sign: func(payload []byte, _ string) (string, []byte, error) {
				return requester["key"].(string), ed25519.Sign(private, payload), nil
			}}
			client := humanEnrollmentClient(human, c["origin"].(string))
			issued, err := c["signed_at"].(json.Number).Int64()
			if err != nil {
				t.Fatal(err)
			}
			client.Now = func() time.Time { return time.Unix(issued, 0) }
			body, err := base64.RawURLEncoding.DecodeString(c["body"].(string))
			if err != nil {
				t.Fatal(err)
			}
			req, err := client.SignedRequest(t.Context(), purpose, body)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, body) || req.Header.Get("Authorization") != c["authorization"] || req.URL.Path != c["path"] {
				t.Fatal("human callback changed the frozen wire")
			}
		})
	}
	if count == 0 {
		t.Fatal("no frozen human enrollment requests exercised")
	}
}
