package awid

// The child request/response file exchange for self-custodial issuance and
// local re-sign (docs/id-certificates.md §6, "Self-custodial child requests
// and re-sign transport"). A request proves key possession only; it never
// admits an identity or authorizes a signature.
import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

const (
	IDCertificateRequestPrefix = "aweb.id-certificate-request/1\n"
	// IDCertificateRequestMaxBytes caps request and response files alike.
	IDCertificateRequestMaxBytes = 8192
)

var idCertificateUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IDCertificateRequestSigningBytes are the exact bytes the child signs with
// its subject key.
func IDCertificateRequestSigningBytes(request map[string]any) ([]byte, error) {
	raw, err := idCertificateCanonical(request)
	if err != nil {
		return nil, err
	}
	return append([]byte(IDCertificateRequestPrefix), raw...), nil
}

// SignIDCertificateRequest signs request with its subject's key and returns
// the canonical signed request file, checked as a receiver would parse it.
// sign must answer with the request's own subject_key.
func SignIDCertificateRequest(request map[string]any, sign IDCertificateSigner) ([]byte, error) {
	payload, err := IDCertificateRequestSigningBytes(request)
	if err != nil {
		return nil, err
	}
	signer, signature, err := sign(payload)
	if err != nil {
		return nil, err
	}
	if signer != request["subject_key"] {
		return nil, idCertificateRefusal("invalid_proof")
	}
	raw, err := idCertificateCanonical(map[string]any{"request": request, "signature": base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		return nil, err
	}
	if _, err := ParseIDCertificateRequest(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// IDKeyFingerprint is the fingerprint both sides compare out of band: the
// first 16 bytes of SHA-256 over the raw public key, in four hyphenated
// groups of eight lowercase hex digits.
func IDKeyFingerprint(didKey string) (string, error) {
	if !idCertificateIDValid(didKey, true) {
		return "", idCertificateRefusal("invalid_shape")
	}
	k, err := ExtractPublicKey(didKey)
	if err != nil {
		return "", idCertificateRefusal("invalid_shape")
	}
	sum := sha256.Sum256(k)
	h := hex.EncodeToString(sum[:16])
	return strings.Join([]string{h[0:8], h[8:16], h[16:24], h[24:32]}, "-"), nil
}

// ParseIDCertificateRequest strictly decodes a request file and checks the
// subject key's proof of possession.
func ParseIDCertificateRequest(raw []byte) (map[string]any, error) {
	if len(raw) > IDCertificateRequestMaxBytes {
		return nil, idCertificateRefusal("bundle_too_large")
	}
	signed, err := idCertificateDecodeCanonical(raw)
	if err != nil {
		return nil, err
	}
	invalid := idCertificateRefusal("invalid_shape")
	if !idCertificateExactFields(signed, "request", "signature") {
		return nil, invalid
	}
	r, ok := signed["request"].(map[string]any)
	if !ok || !idCertificateExactFields(r, "v", "type", "request_id", "operation", "id", "domain", "parent", "kind", "subject_key", "invitation_id", "old_certificate") {
		return nil, invalid
	}
	if !attestationVersionIsOne(r["v"]) || r["type"] != "aweb.id-certificate-request" || !idCertificateIsUUID(r["request_id"]) {
		return nil, invalid
	}
	if err := idCertificateBinding(r); err != nil {
		return nil, err
	}
	subject, ok := r["subject_key"].(string)
	if !ok || !idCertificateIDValid(subject, true) {
		return nil, invalid
	}
	id := r["id"].(string)
	if strings.HasPrefix(id, "did:key:") && id != subject {
		return nil, invalid
	}
	switch r["operation"] {
	case "issue":
		if !idCertificateIsUUID(r["invitation_id"]) || r["old_certificate"] != nil {
			return nil, invalid
		}
	case "resign":
		old, ok := r["old_certificate"].(map[string]any)
		if r["invitation_id"] != nil || r["kind"] != "agent" || !strings.HasPrefix(id, "did:key:") || !ok {
			return nil, invalid
		}
		if _, err := idCertificateShape(old); err != nil {
			return nil, err
		}
	default:
		return nil, invalid
	}
	b, err := idSignatureBytes(signed["signature"])
	if err != nil {
		return nil, err
	}
	if err := idStrictVerify(subject, b, func() ([]byte, error) { return IDCertificateRequestSigningBytes(r) }); err != nil {
		return nil, err
	}
	return signed, nil
}

// EncodeIDCertificateResponse returns the canonical response bytes for a
// request: the ordinary chain ending in the issued child certificate.
func EncodeIDCertificateResponse(requestID string, chain map[string]any) ([]byte, error) {
	response := map[string]any{"v": 1, "request_id": requestID, "chain": chain}
	if err := idCertificateResponseShape(response); err != nil {
		return nil, err
	}
	raw, err := idCertificateCanonical(response)
	if err != nil {
		return nil, err
	}
	if len(raw) > IDCertificateRequestMaxBytes {
		return nil, idCertificateRefusal("bundle_too_large")
	}
	return raw, nil
}

// ParseIDCertificateResponse strictly decodes a response file. Its chain's
// signatures authenticate the result; request_id is correlation only.
func ParseIDCertificateResponse(raw []byte) (map[string]any, error) {
	if len(raw) > IDCertificateRequestMaxBytes {
		return nil, idCertificateRefusal("bundle_too_large")
	}
	response, err := idCertificateDecodeCanonical(raw)
	if err != nil {
		return nil, err
	}
	if err := idCertificateResponseShape(response); err != nil {
		return nil, err
	}
	return response, nil
}

func idCertificateResponseShape(response map[string]any) error {
	if !idCertificateExactFields(response, "v", "request_id", "chain") || !attestationVersionIsOne(response["v"]) || !idCertificateIsUUID(response["request_id"]) {
		return idCertificateRefusal("invalid_shape")
	}
	chain, ok := response["chain"].(map[string]any)
	if !ok {
		return idCertificateRefusal("invalid_shape")
	}
	raw, err := idCertificateCanonical(chain)
	if err != nil {
		return err
	}
	if len(raw) > IDChainMaxBytes {
		return idCertificateRefusal("bundle_too_large")
	}
	return idCertificateBundleShape(chain)
}

func idCertificateIsUUID(value any) bool {
	s, ok := value.(string)
	return ok && idCertificateUUID.MatchString(s)
}
