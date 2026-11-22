package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// custodyAdmission binds one verified session proof to the resident and grant.
type custodyAdmission struct {
	grantID, sessionDIDKey, teamID                   string
	subjectDIDAW, subjectDIDKey, audience, timestamp string
	scope                                            custodyAdmissionScope
}

type custodyAdmissionScope string

const (
	custodyAppSnapshot custodyAdmissionScope = ""
	custodyMailSend    custodyAdmissionScope = "mail.send"
	custodyChatSend    custodyAdmissionScope = "chat.send"
	custodyMailRead    custodyAdmissionScope = "mail.read"
	custodyChatRead    custodyAdmissionScope = "chat.read"
)

func custodySendScope(kind string) custodyAdmissionScope {
	if kind == "mail" {
		return custodyMailSend
	}
	return custodyChatSend
}
func custodyReadScope(kind string) custodyAdmissionScope {
	if kind == "mail" {
		return custodyMailRead
	}
	return custodyChatRead
}

// admitCustodyRequest applies the same resident, freshness, session, team and
// scope rule to every signing operation (docs/identity.md: local resident custody).
// Callers verify the operation-specific proof before entering this owner.
func (s *custodyService) admitCustodyRequest(ctx context.Context, request custodyAdmission) (custodyGrantStatus, error) {
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(request.timestamp))
	if err != nil {
		return custodyGrantStatus{}, fmt.Errorf("bad_timestamp")
	}
	if s.now().Sub(ts) > 60*time.Second || ts.Sub(s.now()) > 60*time.Second {
		return custodyGrantStatus{}, fmt.Errorf("bad_timestamp")
	}
	if strings.TrimSpace(request.audience) != "local-resident-custody:"+strings.TrimSpace(s.serviceID) {
		return custodyGrantStatus{}, fmt.Errorf("bad_audience")
	}
	if request.subjectDIDKey != s.identity.DID || (request.subjectDIDAW != "" && request.subjectDIDAW != s.identity.StableID) {
		return custodyGrantStatus{}, fmt.Errorf("grant_subject_mismatch")
	}
	grantStatus := s.clientDeps(ctx).grantStatus
	if grantStatus == nil {
		return custodyGrantStatus{}, fmt.Errorf("grant_freshness_unavailable")
	}
	// Custody checks retain their short freshness/read budget within the calling request.
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := grantStatus(freshCtx, request.grantID)
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
	if strings.TrimSpace(st.GrantDIDKey) != strings.TrimSpace(request.sessionDIDKey) {
		return st, fmt.Errorf("grant_session_mismatch")
	}
	if strings.TrimSpace(st.TeamID) != strings.TrimSpace(request.teamID) {
		return st, fmt.Errorf("grant_team_mismatch")
	}
	// An empty requiredScope means authority comes from the resident's
	// mint-time app tool snapshot rather than a server grant scope.
	if request.scope != custodyAppSnapshot {
		ok := false
		for _, sc := range st.Scopes {
			if strings.TrimSpace(sc) == string(request.scope) {
				ok = true
			}
		}
		if !ok {
			return st, fmt.Errorf("grant_scope_denied")
		}
	}
	return st, nil
}
