// A stack-free sensitivity probe of the production evidence verifier. The
// original export and successful journey verdict are explicit frozen test
// inputs, not a new portable trust format or a live registry observation.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/approval"
	"github.com/awebai/aw/awid"
)

func object(value any) map[string]any { return value.(map[string]any) }
func text(value any) string           { return value.(string) }
func load(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	value, err := proof.Parse(raw)
	if err != nil {
		panic(err)
	}
	return value
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: probe ORIGINAL_EXPORT ORIGINAL_CHECKED_VERDICT ALTERED_EXPORT")
		os.Exit(2)
	}
	original, observed, altered := load(os.Args[1]), load(os.Args[2]), load(os.Args[3])
	if observed["identity_valid"] != true || observed["kind"] != "human" {
		panic("original journey did not verify this human")
	}
	baseline := object(observed["evidence"].([]any)[0])
	checkedLink := object(baseline["link"])
	link := approval.Link{ID: text(observed["id"]), Key: text(checkedLink["key"]), Certificate: text(checkedLink["certificate"])}
	chain := object(original["id_chain"])
	certificate := object(object(chain["certificates"].([]any)[0])["certificate"])
	digest, err := awid.IDCertificateID(certificate)
	if err != nil || digest != link.Certificate || certificate["id"] != link.ID || checkedLink["id"] != link.ID {
		panic("original checked certificate binding differs")
	}
	issuer := text(certificate["issuer_key"])
	issuerKey, err := awid.ExtractPublicKey(issuer)
	if err != nil {
		panic(err)
	}
	asOf, err := baseline["as_of"].(json.Number).Int64()
	if err != nil {
		panic(err)
	}
	trust := proof.Trust{Person: link.ID, IdentityKey: link.Key, Certificate: link.Certificate,
		Organisation: text(observed["domain"]), Issuer: issuer, IssuerPublicKey: issuerKey, ObservedAt: asOf}

	var message awid.MessageEnvelope
	if json.Unmarshal([]byte(text(altered["signed_payload"])), &message) != nil {
		panic("malformed original signed message")
	}
	status, err := awid.VerifySignedPayload(text(altered["signed_payload"]), text(altered["signature"]), message.FromDID, text(altered["signing_key_id"]))
	if err != nil || status != awid.Verified || message.FromStableID != link.ID || message.FromDID != link.Key {
		panic("signed sender differs from the frozen checked subject")
	}
	preflight := awid.VerifyIDChain(object(altered["id_chain"]), awid.IDChainSubject{ID: link.ID, DIDKey: link.Key}, nil, trust.Organisation)
	if preflight.Reason != "evidence_unavailable" {
		// A broken presented link is refused before any network lookup, exactly
		// as in aw verify. Do not call an outage a sensitivity success.
		if preflight.IdentityValid == nil || *preflight.IdentityValid {
			panic("unexpected preflight without public status")
		}
		observed["identity_valid"], observed["reason"] = false, preflight.Reason
		observed["human_id"], observed["kind"], observed["evidence"] = nil, nil, nil
	} else {
		var statement, receipt map[string]any
		for _, raw := range object(altered["evidence"])["links"].([]any) {
			entry := object(raw)
			if entry["certificate"] == link.Certificate {
				statement = object(entry["statement"])
				if entry["receipt"] != nil {
					receipt = object(entry["receipt"])
				}
			}
		}
		// This is the exact public Go function called by exportEvidenceReports.
		// Both trust and time stay at the original independently checked instant.
		report := approval.CheckCreationEvidence(link, statement, receipt, &trust, &trust, asOf)
		observed["evidence"] = []approval.EvidenceReport{report}
	}
	if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil {
		panic(err)
	}
}
