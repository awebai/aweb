package awid

// Pure codecs for docs/id-certificates.md. Signature validity is not parent
// authority or current identity validity; the chain verifier checks those facts.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"github.com/mr-tron/base58"
)

const (
	IDCertificatePrefix   = "aweb.id-certificate/1\n"
	IDChainMaxDepth       = 8
	IDChainMaxBytes       = 6144
	IDChainHeaderMaxBytes = 8192
)

var (
	idCertificateLabel   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	idCertificateInteger = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
	idCertificateB64URL  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// IDCertificateError carries a stable refusal code, independent of prose.
type IDCertificateError struct{ Code string }

func (e *IDCertificateError) Error() string  { return e.Code }
func idCertificateRefusal(code string) error { return &IDCertificateError{Code: code} }
func IDCertificateErrorCode(err error) string {
	var e *IDCertificateError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
func idCertificateJSONValue(value any) error {
	switch v := value.(type) {
	case nil, bool, int, int64, uint64:
		return nil
	case json.Number:
		if !idCertificateInteger.MatchString(v.String()) {
			return idCertificateRefusal("invalid_shape")
		}
	case string:
		if !utf8.ValidString(v) {
			return idCertificateRefusal("invalid_json")
		}
	case []any:
		for _, item := range v {
			if err := idCertificateJSONValue(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, item := range v {
			if !utf8.ValidString(k) {
				return idCertificateRefusal("invalid_json")
			}
			if err := idCertificateJSONValue(item); err != nil {
				return err
			}
		}
	default:
		return idCertificateRefusal("invalid_shape")
	}
	return nil
}
func idCertificateCanonical(value any) ([]byte, error) {
	if err := idCertificateJSONValue(value); err != nil {
		return nil, err
	}
	raw, err := CanonicalJSONValue(value)
	if err != nil {
		return nil, idCertificateRefusal("invalid_json")
	}
	// Go escapes these JSON codepoints even with EscapeHTML disabled. Process
	// complete escapes so a literal backslash-u sequence remains unchanged.
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == '\\' && i+1 < len(raw) {
			if strings.HasPrefix(raw[i:], `\u2028`) {
				out = append(out, []byte("\u2028")...)
				i += 6
			} else if strings.HasPrefix(raw[i:], `\u2029`) {
				out = append(out, []byte("\u2029")...)
				i += 6
			} else {
				out = append(out, raw[i:i+2]...)
				i += 2
			}
		} else {
			out = append(out, raw[i])
			i++
		}
	}
	return out, nil
}

// IDCertificateSigningBytes also supports negative-shape fixtures. Computing a
// digest does not validate or confer authority on a certificate.
func IDCertificateSigningBytes(c map[string]any) ([]byte, error) {
	raw, err := idCertificateCanonical(c)
	if err != nil {
		return nil, err
	}
	return append([]byte(IDCertificatePrefix), raw...), nil
}
func IDCertificateID(c map[string]any) (string, error) {
	raw, err := IDCertificateSigningBytes(c)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
func idCertificateDomain(value any) bool {
	d, ok := value.(string)
	if !ok || len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if !idCertificateLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// A nonidentity canonical point is in the prime subgroup iff undoing its
// cofactor multiplication with 8^-1 mod L recovers the same point. The library
// performs the point arithmetic; no new curve implementation is introduced.
func idCertificatePrimePoint(raw []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil || !bytes.Equal(p.Bytes(), raw) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	eight := [32]byte{8}
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(eight[:])
	inv := new(edwards25519.Scalar).Invert(s)
	q := new(edwards25519.Point).MultByCofactor(p)
	return q.ScalarMult(inv, q).Equal(p) == 1
}

func idCertificateIDValid(value any, keyOnly bool) bool {
	id, ok := value.(string)
	if !ok {
		return false
	}
	if strings.HasPrefix(id, "did:key:") {
		k, e := ExtractPublicKey(id)
		return e == nil && ComputeDIDKey(k) == id && idCertificatePrimePoint(k)
	}
	if !keyOnly && strings.HasPrefix(id, "did:aw:") {
		b, e := base58.Decode(strings.TrimPrefix(id, "did:aw:"))
		return e == nil && len(b) == 20 && "did:aw:"+base58.Encode(b) == id
	}
	return false
}
func idCertificateExactFields(value map[string]any, names ...string) bool {
	if len(value) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}
func idCertificateShape(signed map[string]any) (map[string]any, error) {
	invalid := idCertificateRefusal("invalid_shape")
	if !idCertificateExactFields(signed, "certificate", "signature") {
		return nil, invalid
	}
	c, ok := signed["certificate"].(map[string]any)
	if !ok || !idCertificateExactFields(c, "v", "type", "id", "domain", "parent", "kind", "issuer_key", "issued_at") {
		return nil, invalid
	}
	if !attestationVersionIsOne(c["v"]) || c["type"] != "aweb.id-certificate" {
		return nil, invalid
	}
	if e := idCertificateBinding(c); e != nil {
		return nil, e
	}
	if !idCertificateIDValid(c["issuer_key"], true) {
		return nil, invalid
	}
	issued, ok := c["issued_at"].(string)
	if !ok || !attestationTimestampRE.MatchString(issued) {
		return nil, invalid
	}
	if instant, e := time.Parse("2006-01-02T15:04:05Z", issued); e != nil || instant.Year() < 1 {
		return nil, invalid
	}
	return c, nil
}

// idCertificateBinding checks the id/domain/parent/kind fields that a
// certificate and a child request share.
func idCertificateBinding(c map[string]any) error {
	invalid := idCertificateRefusal("invalid_shape")
	if c["kind"] != "human" && c["kind"] != "agent" {
		return idCertificateRefusal("invalid_kind")
	}
	if !idCertificateIDValid(c["id"], false) {
		return invalid
	}
	if c["kind"] == "human" && !strings.HasPrefix(c["id"].(string), "did:aw:") {
		return invalid
	}
	if !idCertificateDomain(c["domain"]) {
		return idCertificateRefusal("invalid_domain")
	}
	p, ok := c["parent"].(map[string]any)
	if !ok || !idCertificateExactFields(p, "kind", "id") {
		return invalid
	}
	switch p["kind"] {
	case "namespace":
		if !idCertificateDomain(p["id"]) {
			return idCertificateRefusal("invalid_domain")
		}
		if p["id"] != c["domain"] {
			return idCertificateRefusal("domain_mismatch")
		}
	case "identity":
		if !idCertificateIDValid(p["id"], false) {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}
func idCertificateDecodeB64(value string) ([]byte, error) {
	if !idCertificateB64URL.MatchString(value) {
		return nil, idCertificateRefusal("invalid_encoding")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(value)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, idCertificateRefusal("invalid_encoding")
	}
	return b, nil
}

// VerifyIDCertificate checks shape before crypto and uses the caller's
// independently selected issuer key. Full-chain authority checks remain required.
func VerifyIDCertificate(signed map[string]any, issuer string) error {
	c, e := idCertificateShape(signed)
	if e != nil {
		return e
	}
	b, e := idSignatureBytes(signed["signature"])
	if e != nil {
		return e
	}
	if c["issuer_key"] != issuer {
		return idCertificateRefusal("invalid_signature")
	}
	return idStrictVerify(issuer, b, func() ([]byte, error) { return IDCertificateSigningBytes(c) })
}

// idSignatureBytes decodes a strict base64url Ed25519 signature.
func idSignatureBytes(signature any) ([]byte, error) {
	sig, ok := signature.(string)
	if !ok {
		return nil, idCertificateRefusal("invalid_encoding")
	}
	b, e := idCertificateDecodeB64(sig)
	if e != nil {
		return nil, e
	}
	if len(b) != ed25519.SignatureSize {
		return nil, idCertificateRefusal("invalid_encoding")
	}
	return b, nil
}

// idStrictVerify applies the ID Ed25519 profile to a signature by key, whose
// own point the caller has already checked at shape time.
func idStrictVerify(key string, b []byte, payload func() ([]byte, error)) error {
	if !idCertificatePrimePoint(b[:32]) {
		return idCertificateRefusal("invalid_signature")
	}
	// Redundant with crypto/ed25519; kept to pin the profile.
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(b[32:]); err != nil {
		return idCertificateRefusal("invalid_signature")
	}
	k, e := ExtractPublicKey(key)
	if e != nil {
		return idCertificateRefusal("invalid_signature")
	}
	message, e := payload()
	if e != nil {
		return e
	}
	if !ed25519.Verify(k, message, b) {
		return idCertificateRefusal("invalid_signature")
	}
	return nil
}
func idCertificateBundleShape(bundle map[string]any) error {
	if !idCertificateExactFields(bundle, "v", "type", "certificates") || !attestationVersionIsOne(bundle["v"]) || bundle["type"] != "aweb.id-chain" {
		return idCertificateRefusal("invalid_shape")
	}
	certs, ok := bundle["certificates"].([]any)
	if !ok || len(certs) == 0 {
		return idCertificateRefusal("invalid_shape")
	}
	if len(certs) > IDChainMaxDepth {
		return idCertificateRefusal("depth_exceeded")
	}
	for _, v := range certs {
		signed, ok := v.(map[string]any)
		if !ok {
			return idCertificateRefusal("invalid_shape")
		}
		c, e := idCertificateShape(signed)
		if e != nil {
			return e
		}
		if e := VerifyIDCertificate(signed, c["issuer_key"].(string)); e != nil {
			return e
		}
	}
	return nil
}
func EncodeIDChainHeader(bundle map[string]any) (string, error) {
	b, e := idCertificateCanonical(bundle)
	if e != nil {
		return "", e
	}
	if len(b) > IDChainMaxBytes {
		return "", idCertificateRefusal("bundle_too_large")
	}
	if e := idCertificateBundleShape(bundle); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Read each key once; the standard JSON map decoder otherwise overwrites dupes.
func idCertificateJSON(d *json.Decoder) (any, error) {
	token, e := d.Token()
	if e != nil {
		return nil, idCertificateRefusal("invalid_json")
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			out := map[string]any{}
			for d.More() {
				kt, e := d.Token()
				if e != nil {
					return nil, idCertificateRefusal("invalid_json")
				}
				k, ok := kt.(string)
				if !ok {
					return nil, idCertificateRefusal("invalid_json")
				}
				if _, exists := out[k]; exists {
					return nil, idCertificateRefusal("invalid_json")
				}
				item, e := idCertificateJSON(d)
				if e != nil {
					return nil, e
				}
				out[k] = item
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, idCertificateRefusal("invalid_json")
			}
			return out, nil
		case '[':
			out := []any{}
			for d.More() {
				item, e := idCertificateJSON(d)
				if e != nil {
					return nil, e
				}
				out = append(out, item)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, idCertificateRefusal("invalid_json")
			}
			return out, nil
		default:
			return nil, idCertificateRefusal("invalid_json")
		}
	default:
		if e := idCertificateJSONValue(token); e != nil {
			return nil, e
		}
		return token, nil
	}
}
func DecodeIDChainHeader(value string) (map[string]any, error) {
	if len(value) > IDChainHeaderMaxBytes {
		return nil, idCertificateRefusal("bundle_too_large")
	}
	b, e := idCertificateDecodeB64(value)
	if e != nil {
		return nil, e
	}
	if len(b) > IDChainMaxBytes {
		return nil, idCertificateRefusal("bundle_too_large")
	}
	bundle, e := idCertificateDecodeCanonical(b)
	if e != nil {
		return nil, e
	}
	if e := idCertificateBundleShape(bundle); e != nil {
		return nil, e
	}
	return bundle, nil
}

// idCertificateDecodeCanonical strictly decodes one canonical JSON object.
func idCertificateDecodeCanonical(b []byte) (map[string]any, error) {
	if !utf8.Valid(b) {
		return nil, idCertificateRefusal("invalid_json")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	valueJSON, e := idCertificateJSON(d)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, idCertificateRefusal("invalid_json")
	}
	canonical, e := idCertificateCanonical(valueJSON)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(canonical, b) {
		return nil, idCertificateRefusal("noncanonical_json")
	}
	object, ok := valueJSON.(map[string]any)
	if !ok {
		return nil, idCertificateRefusal("invalid_shape")
	}
	return object, nil
}
