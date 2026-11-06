// Test driver for the cross-registry journey. Uses only public SDK entry points.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
