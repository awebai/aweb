// Test driver for the cross-registry journey. Uses only public SDK entry points.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func main() {
	operation := verify
	if len(os.Args) == 2 && os.Args[1] == "cross-domain-fixtures" {
		operation = crossDomainFixtures
	}
	if err := operation(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Build hostile presentations from genuine keys, registrations and certificates
// on the journey's two registries, without changing the original message bytes.
func crossDomainFixtures() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const foreignDomain = "beta.example.net"
	const foreignRegistry = "http://awid-b:8010"
	identity, err := awconfig.LoadWorktreeIdentityFrom("/work/alice/.aw/identity.yaml")
	if err != nil {
		return err
	}
	key, err := awid.LoadSigningKey("/work/alice/.aw/signing.key")
	if err != nil {
		return err
	}
	root, err := awid.LoadSigningKey("/work/home/.awid/controllers/beta.example.net.key")
	if err != nil {
		return err
	}
	client := awid.NewAWIDRegistryClient(nil, nil)
	if err := client.RegisterIdentitySigned(ctx, foreignRegistry, identity.DID, identity.StableID, awid.KeySigner(key)); err != nil {
		return err
	}
	bob, err := awconfig.LoadWorktreeIdentityFrom("/work/bob/.aw/identity.yaml")
	if err != nil {
		return err
	}
	bobChain, err := awconfig.LoadInstalledIDChain("/work/bob/.aw")
	if err != nil {
		return err
	}
	status := awid.NewIDStatusClient(client, nil)
	evidence := status.IDChainEvidence(ctx, bobChain.Bundle, awid.IDChainSubject{ID: bob.StableID, DIDKey: bob.DID}, foreignDomain)
	bundle, err := awid.IssueIDChild(awconfig.IDIssuanceFileStore{Dir: "/work/cross-domain-issuance"},
		awid.IDChild{ID: identity.StableID, Domain: foreignDomain, Parent: map[string]any{"kind": "namespace", "id": foreignDomain}, Kind: "agent"},
		nil, evidence, awid.KeySigner(root), time.Now())
	if err != nil {
		return err
	}
	if _, err := client.RegisterIDCertificateAt(ctx, foreignRegistry, bundle, awid.KeySigner(key), nil, nil); err != nil {
		return err
	}
	subject := awid.IDChainSubject{ID: identity.StableID, DIDKey: identity.DID}
	evidence = status.IDChainEvidence(ctx, bundle, subject, foreignDomain)
	neighbor := awid.VerifyIDChain(bundle, subject, evidence, foreignDomain)
	if neighbor.IdentityValid == nil || !*neighbor.IdentityValid || neighbor.Outcome != "no_human" {
		return fmt.Errorf("foreign-domain neighboring chain is not independently valid: %+v", neighbor)
	}
	// The original registry still fixes the identity's original enrollment.
	original, err := client.ResolveKeyAt(ctx, "http://awid-a:8010", identity.StableID)
	if err != nil {
		return err
	}
	enrollment := original.IDTreeEnrollmentOf(identity.StableID, identity.DID, time.Now())
	if enrollment.State != "enrolled" || enrollment.Domain == nil || *enrollment.Domain != "alpha.example.com" {
		return fmt.Errorf("original authoritative enrollment changed: %+v", enrollment)
	}
	raw, err := os.ReadFile("/envelopes/adopted.json")
	if err != nil {
		return err
	}
	var export map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&export); err != nil {
		return err
	}
	originalBundle := export["id_chain"].(map[string]any)
	for name, presentation := range map[string]map[string]any{
		"foreign-domain": bundle,
		"mixed-domains":  {"v": 1, "type": "aweb.id-chain", "certificates": []any{originalBundle["certificates"].([]any)[0], bundle["certificates"].([]any)[0]}},
	} {
		export["id_chain"] = presentation
		bytes, err := json.Marshal(export)
		if err != nil {
			return err
		}
		if err := os.WriteFile("/envelopes/"+name+".json", bytes, 0o600); err != nil {
			return err
		}
	}
	fmt.Println("PASS: genuine foreign-root chain verifies under its own domain while original key-route enrollment remains alpha.example.com")
	return nil
}

func verify() error {
	var cases []struct {
		Home, ID, DIDKey, Domain, Outcome, HumanID, Kind, Reason string
	}
	f, err := os.Open("/work/journey-public.json")
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&cases); err != nil {
		return err
	}
	client := awid.NewAWIDRegistryClient(nil, nil)
	for _, c := range cases {
		chain, err := awconfig.LoadInstalledIDChain(c.Home)
		if err != nil {
			return err
		}
		if chain == nil {
			return fmt.Errorf("missing constructor chain: %s", c.Home)
		}
		subject, err := chain.Subject(c.DIDKey)
		if err != nil {
			return err
		}
		if subject.ID != c.ID {
			return fmt.Errorf("wrong subject: %s", c.Home)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		evidence := awid.NewIDStatusClient(client, nil).IDChainEvidence(ctx, chain.Bundle, subject, c.Domain)
		cancel()
		r := awid.VerifyIDChain(chain.Bundle, subject, evidence, c.Domain)
		human := ""
		if r.HumanID != nil {
			human = *r.HumanID
		}
		if c.Reason == "revoked" {
			if r.IdentityValid == nil || *r.IdentityValid || r.Outcome != "unknown" || r.HumanID != nil || r.Kind != nil || r.Reason != "revoked" {
				return fmt.Errorf("Go outsider revoked %s: %+v", c.ID, r)
			}
			fmt.Printf("PASS: Go outsider revoked %s %s\n", c.Kind, c.ID)
			continue
		}
		if r.IdentityValid == nil || !*r.IdentityValid || r.Outcome != c.Outcome || r.Kind == nil || *r.Kind != c.Kind || human != c.HumanID || r.Reason != "verified" {
			return fmt.Errorf("Go outsider %s: %+v", c.ID, r)
		}
		fmt.Printf("PASS: Go outsider %s %s %s\n", c.Kind, r.Outcome, c.ID)
	}
	return nil
}
