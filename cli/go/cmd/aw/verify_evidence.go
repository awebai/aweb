package main

import (
	"context"
	"encoding/json"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/approval"
	"github.com/awebai/aw/awid"
)

type evidenceTrust func(context.Context, []any, string, string, string) (*proof.Trust, error)

// The export-side collection only associates portable E/C objects with an
// already checked certificate. It never supplies a trust anchor or chain verdict.
func exportEvidenceReports(ctx context.Context, raw json.RawMessage, bundle awid.ReceivedIDChain, out whoOutput, source evidenceTrust) []approval.EvidenceReport {
	if out.IdentityValid == nil || !*out.IdentityValid || len(out.Chain) == 0 {
		return nil
	}
	certificates, ok := bundle["certificates"].([]any)
	if !ok {
		return nil
	}
	entries := map[string]map[string]any{}
	status, reason := "", ""
	if len(raw) > 0 {
		collection, e := proof.Parse(raw)
		if e != nil {
			status, reason = "invalid", "malformed"
		} else if v, ok := collection["v"].(json.Number); !ok || v != "1" {
			status, reason = "unsupported", "unsupported_version"
		} else {
			links, ok := collection["links"].([]any)
			if !ok || len(collection) != 2 {
				status, reason = "invalid", "malformed"
			} else {
				for _, value := range links {
					entry, ok := value.(map[string]any)
					if !ok {
						status, reason = "invalid", "malformed"
						break
					}
					certificate, ok := entry["certificate"].(string)
					if !ok || certificate == "" || entries[certificate] != nil || len(entry) < 2 || len(entry) > 3 {
						status, reason = "invalid", "malformed"
						break
					}
					for key := range entry {
						if key != "certificate" && key != "statement" && key != "receipt" {
							status, reason = "invalid", "malformed"
						}
					}
					if _, ok = entry["statement"].(map[string]any); !ok {
						status, reason = "invalid", "malformed"
						break
					}
					if value, exists := entry["receipt"]; exists && value != nil {
						if _, ok = value.(map[string]any); !ok {
							status, reason = "invalid", "malformed"
							break
						}
					}
					entries[certificate] = entry
				}
			}
		}
	}
	reports := make([]approval.EvidenceReport, 0, len(certificates))
	for i, value := range certificates {
		signed, ok := value.(map[string]any)
		if !ok {
			continue
		}
		certificate, ok := signed["certificate"].(map[string]any)
		if !ok {
			continue
		}
		digest, e := awid.IDCertificateID(certificate)
		if e != nil {
			continue
		}
		id, _ := certificate["id"].(string)
		link := approval.Link{Position: i, ID: id, Certificate: digest}
		empty := approval.CheckCreationEvidence(link, nil, nil, nil, nil, time.Now().Unix())
		if status != "" {
			empty.Presence = "present"
			empty.Statement = approval.Check{Status: status, Reason: reason}
			empty.Proof = approval.Check{Status: "not_evaluated", Reason: "statement_unverified"}
			reports = append(reports, empty)
			continue
		}
		entry := entries[digest]
		if entry == nil {
			reports = append(reports, empty)
			continue
		}
		statement, _ := entry["statement"].(map[string]any)
		receipt, _ := entry["receipt"].(map[string]any)
		evidence, _ := statement["evidence"].(map[string]any)
		subject, _ := evidence["subject"].(map[string]any)
		link.Key, _ = subject["key"].(string)
		var trust *proof.Trust
		if source != nil && link.Key != "" {
			trust, _ = source(ctx, certificates[:i+1], id, link.Key, out.Domain)
		}
		reports = append(reports, approval.CheckHumanEvidence(link, statement, receipt, trust, trust, time.Now().Unix()))
	}
	return reports
}
