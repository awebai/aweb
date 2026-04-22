package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const (
	doctorSupportBundleSchema = "support_bundle.v1"
	doctorRedactedMarker      = "[REDACTED]"
)

type doctorSupportBundleInfo struct {
	Schema           string                              `json:"schema"`
	GeneratedBy      string                              `json:"generated_by"`
	SafeToShare      bool                                `json:"safe_to_share"`
	Platform         doctorSupportBundlePlatform         `json:"platform"`
	LocalMetadata    doctorSupportBundleLocalMetadata    `json:"local_metadata"`
	RedactionSummary doctorSupportBundleRedactionSummary `json:"redaction_summary"`
}

type doctorSupportBundlePlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type doctorSupportBundleLocalMetadata struct {
	WorkspaceYAMLPresent   bool                                    `json:"workspace_yaml_present"`
	IdentityYAMLPresent    bool                                    `json:"identity_yaml_present"`
	SigningKeyPresent      bool                                    `json:"signing_key_present"`
	TeamCertificatePresent bool                                    `json:"team_certificate_present"`
	AwebURL                string                                  `json:"aweb_url,omitempty"`
	RegistryURL            string                                  `json:"registry_url,omitempty"`
	TeamID                 string                                  `json:"team_id,omitempty"`
	WorkspaceID            string                                  `json:"workspace_id,omitempty"`
	Alias                  string                                  `json:"alias,omitempty"`
	RoleName               string                                  `json:"role_name,omitempty"`
	Lifetime               string                                  `json:"lifetime,omitempty"`
	Custody                string                                  `json:"custody,omitempty"`
	DIDKey                 string                                  `json:"did_key,omitempty"`
	StableID               string                                  `json:"stable_id,omitempty"`
	Address                string                                  `json:"address,omitempty"`
	Hostname               string                                  `json:"hostname,omitempty"`
	WorkspacePath          string                                  `json:"workspace_path,omitempty"`
	Certificate            *doctorSupportBundleCertificateMetadata `json:"certificate,omitempty"`
}

type doctorSupportBundleCertificateMetadata struct {
	TeamID        string `json:"team_id,omitempty"`
	Alias         string `json:"alias,omitempty"`
	MemberDIDKey  string `json:"member_did_key,omitempty"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Lifetime      string `json:"lifetime,omitempty"`
	TeamDIDKey    string `json:"team_did_key,omitempty"`
}

type doctorSupportBundleRedactionSummary struct {
	RuleVersion string         `json:"rule_version"`
	Count       int            `json:"count"`
	ByReason    map[string]int `json:"by_reason,omitempty"`
}

type doctorKnownSecret struct {
	Value  string
	Reason string
}

func buildDoctorSupportBundle(opts doctorRunOptions) (doctorOutput, []doctorKnownSecret, error) {
	out := buildDoctorOutput(opts)
	workingDir := strings.TrimSpace(out.Subject.WorkingDir)
	if workingDir == "" {
		workingDir = "."
	}
	knownSecrets := collectDoctorKnownSecrets(workingDir)
	out.SupportBundle = &doctorSupportBundleInfo{
		Schema:      doctorSupportBundleSchema,
		GeneratedBy: "aw doctor support-bundle",
		SafeToShare: true,
		Platform: doctorSupportBundlePlatform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		LocalMetadata: collectDoctorSupportBundleLocalMetadata(workingDir),
	}
	out = redactDoctorSupportBundle(out, knownSecrets)
	if out.SupportBundle != nil {
		out.SupportBundle.RedactionSummary = summarizeDoctorRedactions(out.Redactions)
	}
	return out, knownSecrets, nil
}

func collectDoctorSupportBundleLocalMetadata(workingDir string) doctorSupportBundleLocalMetadata {
	meta := doctorSupportBundleLocalMetadata{}
	workspace, _, err := loadDoctorWorkspaceFromDir(workingDir)
	if err == nil && workspace != nil {
		meta.WorkspaceYAMLPresent = true
		if safe, err := sanitizeLocalURLForOutput(workspace.AwebURL); err == nil {
			meta.AwebURL = safe
		}
		meta.Hostname = strings.TrimSpace(workspace.Hostname)
		meta.WorkspacePath = strings.TrimSpace(workspace.WorkspacePath)
		teamState, _ := awconfig.LoadTeamState(workingDir)
		if membership := awconfig.ActiveMembershipFor(workspace, teamState); membership != nil {
			meta.TeamID = strings.TrimSpace(membership.TeamID)
			meta.WorkspaceID = strings.TrimSpace(membership.WorkspaceID)
			meta.Alias = strings.TrimSpace(membership.Alias)
			meta.RoleName = strings.TrimSpace(membership.RoleName)
			certPath := resolveWorkspaceCertificatePath(workingDir, membership.CertPath)
			if strings.TrimSpace(certPath) != "" {
				if cert, err := awid.LoadTeamCertificate(certPath); err == nil && cert != nil {
					meta.TeamCertificatePresent = true
					meta.Lifetime = strings.TrimSpace(cert.Lifetime)
					meta.DIDKey = strings.TrimSpace(cert.MemberDIDKey)
					meta.StableID = strings.TrimSpace(cert.MemberDIDAW)
					meta.Address = strings.TrimSpace(cert.MemberAddress)
					meta.Certificate = &doctorSupportBundleCertificateMetadata{
						TeamID:        strings.TrimSpace(cert.Team),
						Alias:         strings.TrimSpace(cert.Alias),
						MemberDIDKey:  strings.TrimSpace(cert.MemberDIDKey),
						MemberDIDAW:   strings.TrimSpace(cert.MemberDIDAW),
						MemberAddress: strings.TrimSpace(cert.MemberAddress),
						Lifetime:      strings.TrimSpace(cert.Lifetime),
						TeamDIDKey:    strings.TrimSpace(cert.TeamDIDKey),
					}
				}
			}
		}
	}
	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	if identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath); err == nil && identity != nil {
		meta.IdentityYAMLPresent = true
		meta.Lifetime = firstNonEmpty(strings.TrimSpace(identity.Lifetime), meta.Lifetime)
		meta.Custody = strings.TrimSpace(identity.Custody)
		meta.DIDKey = firstNonEmpty(strings.TrimSpace(identity.DID), meta.DIDKey)
		meta.StableID = firstNonEmpty(strings.TrimSpace(identity.StableID), meta.StableID)
		meta.Address = firstNonEmpty(strings.TrimSpace(identity.Address), meta.Address)
		if safe, err := sanitizeLocalURLForOutput(identity.RegistryURL); err == nil {
			meta.RegistryURL = safe
		}
	}
	if _, err := os.Stat(awconfig.WorktreeSigningKeyPath(workingDir)); err == nil {
		meta.SigningKeyPresent = true
	}
	return meta
}

func collectDoctorKnownSecrets(workingDir string) []doctorKnownSecret {
	var secrets []doctorKnownSecret
	add := func(value, reason string) {
		value = strings.TrimSpace(value)
		if len(value) < 4 {
			return
		}
		for _, existing := range secrets {
			if existing.Value == value {
				return
			}
		}
		secrets = append(secrets, doctorKnownSecret{Value: value, Reason: reason})
	}
	addURLSecrets := func(raw string) {
		raw = strings.TrimSpace(raw)
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return
		}
		if parsed.User != nil {
			add(parsed.User.String(), "url_userinfo")
		}
		if parsed.RawQuery != "" {
			add(parsed.RawQuery, "url_query")
		}
		if parsed.Fragment != "" {
			add(parsed.Fragment, "url_fragment")
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			add(raw, "url_with_credentials")
		}
	}

	if workspace, _, err := loadDoctorWorkspaceFromDir(workingDir); err == nil && workspace != nil {
		add(workspace.APIKey, "api_key")
		addURLSecrets(workspace.AwebURL)
		teamState, _ := awconfig.LoadTeamState(workingDir)
		if membership := awconfig.ActiveMembershipFor(workspace, teamState); membership != nil {
			certPath := resolveWorkspaceCertificatePath(workingDir, membership.CertPath)
			if strings.TrimSpace(certPath) != "" {
				if data, err := os.ReadFile(certPath); err == nil {
					add(string(data), "raw_team_certificate")
				}
				if cert, err := awid.LoadTeamCertificate(certPath); err == nil && cert != nil {
					add(cert.Signature, "certificate_signature")
				}
			}
		}
	}
	if identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())); err == nil && identity != nil {
		addURLSecrets(identity.RegistryURL)
	}
	addURLSecrets(os.Getenv("AWID_REGISTRY_URL"))
	if data, err := os.ReadFile(awconfig.WorktreeSigningKeyPath(workingDir)); err == nil {
		add(string(data), "secret_key_material")
	}
	return secrets
}

func redactDoctorSupportBundle(out doctorOutput, knownSecrets []doctorKnownSecret) doctorOutput {
	data, err := json.Marshal(out)
	if err != nil {
		return out
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return out
	}
	redactions := append([]doctorRedaction{}, out.Redactions...)
	generic = redactDoctorValue(generic, "$", knownSecrets, &redactions)
	data, err = json.Marshal(generic)
	if err != nil {
		return out
	}
	var redacted doctorOutput
	if err := json.Unmarshal(data, &redacted); err != nil {
		return out
	}
	redacted.Redactions = dedupeDoctorRedactions(redactions)
	return redacted
}

func redactDoctorValue(value any, path string, knownSecrets []doctorKnownSecret, redactions *[]doctorRedaction) any {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			childPath := path + "." + key
			if doctorSensitiveKey(key) {
				if !isEmptyDoctorValue(child) {
					*redactions = append(*redactions, doctorRedaction{Field: childPath, Reason: doctorSensitiveKeyReason(key)})
				}
				v[key] = doctorRedactedMarker
				continue
			}
			v[key] = redactDoctorValue(child, childPath, knownSecrets, redactions)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = redactDoctorValue(child, fmt.Sprintf("%s[%d]", path, i), knownSecrets, redactions)
		}
		return v
	case string:
		return redactDoctorString(v, path, knownSecrets, redactions)
	default:
		return v
	}
}

func redactDoctorString(value, path string, knownSecrets []doctorKnownSecret, redactions *[]doctorRedaction) string {
	redacted := value
	if sanitized, ok := sanitizeDoctorStringURL(redacted); ok && sanitized != redacted {
		redacted = sanitized
		*redactions = append(*redactions, doctorRedaction{Field: path, Reason: "url_credentials"})
	}
	for _, secret := range sortedDoctorKnownSecrets(knownSecrets) {
		if secret.Value == "" || !strings.Contains(redacted, secret.Value) {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret.Value, doctorRedactedMarker)
		*redactions = append(*redactions, doctorRedaction{Field: path, Reason: secret.Reason})
	}
	if doctorStringLooksSensitive(redacted) {
		*redactions = append(*redactions, doctorRedaction{Field: path, Reason: "credential_pattern"})
		return doctorRedactedMarker
	}
	return redacted
}

func sortedDoctorKnownSecrets(secrets []doctorKnownSecret) []doctorKnownSecret {
	out := append([]doctorKnownSecret{}, secrets...)
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Value) > len(out[j].Value)
	})
	return out
}

func sanitizeDoctorStringURL(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed != value || trimmed == "" {
		return value, false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return value, false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return value, false
	}
	changed := parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != ""
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), changed
}

func doctorSensitiveKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "api_key", "apikey", "authorization", "cookie", "set-cookie", "bearer", "token", "access_token", "refresh_token", "private_key", "signing_key", "encrypted_key", "ciphertext", "signature", "team_certificate", "certificate_signature":
		return true
	default:
		return strings.Contains(key, "secret") || strings.Contains(key, "private_key") || strings.Contains(key, "ciphertext")
	}
}

func doctorSensitiveKeyReason(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch {
	case strings.Contains(key, "cookie"):
		return "cookie"
	case strings.Contains(key, "authorization") || strings.Contains(key, "bearer") || strings.Contains(key, "token") || strings.Contains(key, "api_key") || strings.Contains(key, "apikey"):
		return "credential"
	case strings.Contains(key, "signature"):
		return "signature"
	case strings.Contains(key, "ciphertext") || strings.Contains(key, "encrypted"):
		return "encrypted_key_ciphertext"
	default:
		return "secret"
	}
}

func doctorStringLooksSensitive(value string) bool {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(value, "-----BEGIN ") && strings.Contains(value, "PRIVATE KEY-----"):
		return true
	case strings.Contains(lower, "bearer "):
		return true
	case strings.Contains(lower, "authorization:"):
		return true
	case strings.Contains(lower, "cookie:"):
		return true
	case strings.Contains(value, "aw_sk_"):
		return true
	default:
		return false
	}
}

func isEmptyDoctorValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		return false
	}
}

func summarizeDoctorRedactions(redactions []doctorRedaction) doctorSupportBundleRedactionSummary {
	summary := doctorSupportBundleRedactionSummary{
		RuleVersion: "support-bundle-redactions.v1",
		Count:       len(redactions),
		ByReason:    map[string]int{},
	}
	for _, redaction := range redactions {
		reason := strings.TrimSpace(redaction.Reason)
		if reason == "" {
			reason = "unspecified"
		}
		summary.ByReason[reason]++
	}
	if len(summary.ByReason) == 0 {
		summary.ByReason = nil
	}
	return summary
}

func dedupeDoctorRedactions(redactions []doctorRedaction) []doctorRedaction {
	seen := map[string]bool{}
	out := make([]doctorRedaction, 0, len(redactions))
	for _, redaction := range redactions {
		field := strings.TrimSpace(redaction.Field)
		reason := strings.TrimSpace(redaction.Reason)
		if field == "" || reason == "" {
			continue
		}
		key := field + "\x00" + reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, doctorRedaction{Field: field, Reason: reason})
	}
	return out
}

func scanDoctorSupportBundleBytes(data []byte, knownSecrets []doctorKnownSecret) error {
	text := string(data)
	for _, secret := range knownSecrets {
		if strings.TrimSpace(secret.Value) == "" {
			continue
		}
		if strings.Contains(text, secret.Value) {
			return fmt.Errorf("support bundle redaction failed for %s", secret.Reason)
		}
	}
	return nil
}

func doctorRequestIDFromError(err error) (string, bool) {
	if body, ok := awid.HTTPErrorBody(err); ok {
		return extractDoctorRequestID(body)
	}
	var registryErr *awid.RegistryError
	if errors.As(err, &registryErr) {
		return extractDoctorRequestID(registryErr.Detail)
	}
	return "", false
}

func extractDoctorRequestID(body string) (string, bool) {
	var raw any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return "", false
	}
	if value, ok := extractDoctorRequestIDFromMap(raw); ok {
		return value, true
	}
	return "", false
}

func extractDoctorRequestIDFromMap(value any) (string, bool) {
	obj, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	for _, key := range []string{"request_id", "trace_id", "correlation_id"} {
		if id, ok := printableDoctorScalar(obj[key]); ok {
			return id, true
		}
	}
	if detail, ok := obj["detail"].(map[string]any); ok {
		for _, key := range []string{"request_id", "trace_id", "correlation_id"} {
			if id, ok := printableDoctorScalar(detail[key]); ok {
				return id, true
			}
		}
	}
	return "", false
}

func printableDoctorScalar(value any) (string, bool) {
	var out string
	switch v := value.(type) {
	case string:
		out = strings.TrimSpace(v)
	case float64:
		out = strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return "", false
	default:
		return "", false
	}
	if out == "" || !utf8.ValidString(out) {
		return "", false
	}
	for _, r := range out {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return capDoctorRequestID(out, 128), true
}

func capDoctorRequestID(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	count := 0
	for idx := range value {
		if count == maxRunes {
			return value[:idx]
		}
		count++
	}
	return value
}
