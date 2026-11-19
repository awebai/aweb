package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *custodyService) validateE2EECommon(ctx context.Context, op string, reqFields map[string]string, nonce, timestamp string, requiredScope string) (custodyGrantStatus, error) {
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(timestamp))
	if err != nil {
		return custodyGrantStatus{}, fmt.Errorf("bad_timestamp")
	}
	if s.now().Sub(ts) > 60*time.Second || ts.Sub(s.now()) > 60*time.Second {
		return custodyGrantStatus{}, fmt.Errorf("bad_timestamp")
	}
	if strings.TrimSpace(reqFields["aud"]) != "local-resident-custody:"+strings.TrimSpace(s.serviceID) {
		return custodyGrantStatus{}, fmt.Errorf("bad_audience")
	}
	if reqFields["subject_did_key"] != s.identity.DID || (reqFields["subject_did_aw"] != "" && reqFields["subject_did_aw"] != s.identity.StableID) {
		return custodyGrantStatus{}, fmt.Errorf("grant_subject_mismatch")
	}
	grantStatus := s.clientDeps(ctx).grantStatus
	if grantStatus == nil {
		return custodyGrantStatus{}, fmt.Errorf("grant_freshness_unavailable")
	}
	// Custody checks retain their short freshness/read budget within the calling request.
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := grantStatus(freshCtx, reqFields["grant_id"])
	if err != nil {
		s.reportFailure("check grant freshness", "grant_freshness_unavailable", err)
		return custodyGrantStatus{}, fmt.Errorf("grant_freshness_unavailable")
	}
	if !st.Active {
		switch firstNonEmpty(strings.TrimSpace(st.EffectiveStatus), strings.TrimSpace(st.Status)) {
		case "expired":
			return st, fmt.Errorf("grant_expired")
		case "revoked":
			return st, fmt.Errorf("grant_revoked")
		case "issuer_revoked":
			return st, fmt.Errorf("grant_issuer_revoked")
		case "issuer_not_registered":
			return st, fmt.Errorf("grant_issuer_not_registered")
		case "subject_inactive":
			return st, fmt.Errorf("grant_subject_inactive")
		}
		return st, fmt.Errorf("grant_scope_denied")
	}
	if strings.TrimSpace(st.ExpiresAt) == "" {
		return st, fmt.Errorf("grant_freshness_unavailable")
	}
	if err := checkGrantExpiry(st.ExpiresAt, s.now()); err != nil {
		return st, err
	}
	if strings.TrimSpace(st.GrantDIDKey) != strings.TrimSpace(reqFields["session_did_key"]) {
		return st, fmt.Errorf("grant_session_mismatch")
	}
	if strings.TrimSpace(st.TeamID) != strings.TrimSpace(reqFields["team_id"]) {
		return st, fmt.Errorf("grant_team_mismatch")
	}
	// An empty requiredScope means authority comes from the resident's
	// mint-time app tool snapshot rather than a server grant scope.
	if requiredScope != "" {
		ok := false
		for _, sc := range st.Scopes {
			if strings.TrimSpace(sc) == requiredScope {
				ok = true
			}
		}
		if !ok {
			return st, fmt.Errorf("grant_scope_denied")
		}
	}
	return st, nil
}
