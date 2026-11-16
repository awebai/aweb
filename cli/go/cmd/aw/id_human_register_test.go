package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIssuedHumanPacketBindsTheSelectedPerson(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	signed := vectors["certificates"].(map[string]any)["alice"].(map[string]any)["signed"].(map[string]any)
	cert := signed["certificate"].(map[string]any)
	key := "did:key:z6Mkv3sqpxCwZNXBryG91KcTMHFU2ts48VAccd2idDzN7X4v"
	record := &awconfig.HumanRecord{StableID: cert["id"].(string), DIDKey: key, Domain: cert["domain"].(string)}
	packet := map[string]any{"state": "issued", "person": record.StableID, "identity_key": key, "certificate": signed}
	for _, field := range []string{"", "person", "identity_key"} {
		t.Run(field, func(t *testing.T) {
			copy := map[string]any{}
			for k, v := range packet {
				copy[k] = v
			}
			if field != "" {
				copy[field] = "another-person-or-key"
			}
			raw, err := proof.Canonical(copy)
			if err != nil {
				t.Fatal(err)
			}
			chain, err := parseIssuedHumanChain(raw, record)
			if field != "" {
				if err == nil {
					t.Fatal("accepted certificate handover for another person/key")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			certificates := chain["certificates"].([]any)
			got := certificates[0].(map[string]any)
			if err := awid.VerifyIDCertificate(got, cert["issuer_key"].(string)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
