package a2agw

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

type AuditSink interface {
	RecordA2A(AuditEvent)
}

type AuditEvent struct {
	Stage               string `json:"stage"`
	RequestID           string `json:"request_id,omitempty"`
	RouteID             string `json:"route_id,omitempty"`
	TaskID              string `json:"task_id,omitempty"`
	CallerScopeClass    string `json:"caller_scope_class,omitempty"`
	GatewayIdentityHash string `json:"gateway_identity_hash,omitempty"`
	TargetAddressHash   string `json:"target_address_hash,omitempty"`
	CustodyMode         string `json:"custody_mode,omitempty"`
	Outcome             string `json:"outcome,omitempty"`
	Code                string `json:"code,omitempty"`
	LatencyMS           int64  `json:"latency_ms,omitempty"`
	VerificationTier    string `json:"verification_tier,omitempty"`
}

func (g *Gateway) audit(event AuditEvent) {
	if g == nil || g.auditSink == nil {
		return
	}
	g.auditSink.RecordA2A(event)
}

func auditHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func callerScopeClass(scope string) string {
	switch {
	case strings.HasPrefix(scope, "auth:"):
		return "auth"
	case strings.HasPrefix(scope, "caller:"):
		return "caller"
	case strings.HasPrefix(scope, "anonymous:"):
		return "anonymous"
	case strings.TrimSpace(scope) == "":
		return "unknown"
	default:
		return "other"
	}
}

func latencyMS(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}
	return time.Since(start).Milliseconds()
}
