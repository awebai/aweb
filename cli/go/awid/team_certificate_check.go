package awid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxTeamCertificateHeaderBytes bounds the transport header. A real
// certificate header is well under 4 KiB; anything longer is refused before
// it is decoded.
const MaxTeamCertificateHeaderBytes = 8192

// TeamCertificateReasons are why CheckTeamCertificate refuses a certificate.
// Each is a fault of the certificate presented.
var TeamCertificateReasons = []string{
	"malformed",
	"unsupported_version",
	"invalid_field",
	"member_key_mismatch",
	"bad_signature",
	"revoked",
	"unregistered",
}

// teamCertificateSignature is a signature as every issuer writes it: standard
// base64 without padding.
var teamCertificateSignature = regexp.MustCompile(`^[A-Za-z0-9+/]+$`)

// teamCertificateRequiredFields must each be a non-empty string. The version
// is checked apart. Any other member is signed with the rest and is the
// reader's to interpret.
var teamCertificateRequiredFields = []string{"certificate_id", "team_id", "member_did_key", "alias", "signature"}

// TeamCertificateError is a certificate that CheckTeamCertificate refuses.
// Reason is one of TeamCertificateReasons, or "invalid_team_key" when the
// team key the caller supplied does not decode, which is no fault of the
// certificate. Field names the required field an "invalid_field" is about.
// Nothing a certificate carries, key or value, is in the message.
type TeamCertificateError struct {
	Reason string
	Field  string
}

func (e *TeamCertificateError) Error() string {
	if e.Field == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Field
}

// RegisteredCertificates is the team's registered certificate ids as the
// caller has them. Its zero value states nothing and is refused: a caller
// says either which certificates are registered or that registration is not
// required of it yet.
type RegisteredCertificates struct {
	stated   bool
	required bool
	ids      []string
}

// RegisteredCertificateIDs are the team's registered certificates, from the registry.
func RegisteredCertificateIDs(ids []string) RegisteredCertificates {
	return RegisteredCertificates{stated: true, required: true, ids: ids}
}

// RegistrationNotRequired leaves registration unchecked. It is legal only on
// a surface whose registered-certificate requirement is still switched off.
func RegistrationNotRequired() RegisteredCertificates {
	return RegisteredCertificates{stated: true}
}

// TeamCertificateFacts are what a caller knows apart from the certificate.
// SubjectDIDKey is the key the certificate must name: a request's signer, or
// a delivery's producer. TeamDIDKey is the registry's current key for the
// team the certificate names: a caller resolves it from the certificate's
// team_id, or compares that team_id with the team it resolved the key for,
// before it uses the team_id for anything. The revoked and registered ids
// are the registry's, never the certificate's.
type TeamCertificateFacts struct {
	SubjectDIDKey         string
	TeamDIDKey            string
	RevokedCertificateIDs []string
	Registered            RegisteredCertificates
}

// CheckTeamCertificate checks one team certificate, given as its transport
// header, and returns it. A certificate has no expiry: revocation is its
// only end. It refuses, in this order, for the header's shape, the version,
// the required fields, the subject, the signature ("malformed" when it is
// not unpadded standard base64, then "bad_signature"), revocation and
// registration, with a *TeamCertificateError.
func CheckTeamCertificate(header string, facts TeamCertificateFacts) (map[string]any, error) {
	if !facts.Registered.stated {
		return nil, errors.New("awid: the registered certificates were not stated")
	}
	certificate, err := DecodeTeamCertificate(header)
	if err != nil {
		return nil, err
	}
	version, present := certificate["version"]
	if !present {
		return nil, &TeamCertificateError{Reason: "invalid_field", Field: "version"}
	}
	if number, ok := version.(json.Number); !ok || number.String() != "1" {
		return nil, &TeamCertificateError{Reason: "unsupported_version"}
	}
	for _, name := range teamCertificateRequiredFields {
		value, ok := certificate[name].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, &TeamCertificateError{Reason: "invalid_field", Field: name}
		}
	}
	if certificate["member_did_key"] != facts.SubjectDIDKey {
		return nil, &TeamCertificateError{Reason: "member_key_mismatch"}
	}
	if !teamCertificateSignature.MatchString(certificate["signature"].(string)) {
		return nil, &TeamCertificateError{Reason: "malformed"}
	}
	if err := verifyTeamCertificateObjectSignature(certificate, facts.TeamDIDKey); err != nil {
		return nil, err
	}
	certificateID := certificate["certificate_id"].(string)
	if containsString(facts.RevokedCertificateIDs, certificateID) {
		return nil, &TeamCertificateError{Reason: "revoked"}
	}
	if facts.Registered.required && !containsString(facts.Registered.ids, certificateID) {
		return nil, &TeamCertificateError{Reason: "unregistered"}
	}
	return certificate, nil
}

// DecodeTeamCertificate decodes the header: padded base64 of one JSON
// object, at most MaxTeamCertificateHeaderBytes long, holding only values
// that every verifier re-serialises alike. It checks nothing else: a caller
// reads from it only what it needs to find the registry's facts, and then
// calls CheckTeamCertificate.
func DecodeTeamCertificate(header string) (map[string]any, error) {
	malformed := &TeamCertificateError{Reason: "malformed"}
	if len(header) > MaxTeamCertificateHeaderBytes || strings.ContainsAny(header, "\r\n") {
		return nil, malformed
	}
	data, err := base64.StdEncoding.Strict().DecodeString(header)
	if err != nil || !utf8.Valid(data) {
		return nil, malformed
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, malformed
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, malformed
	}
	certificate, ok := value.(map[string]any)
	if !ok || !hasOnlyPortableValues(certificate) {
		return nil, malformed
	}
	return certificate, nil
}

// hasOnlyPortableValues reports whether every verifier re-serialises value
// to the same bytes: no number that is not an integer, no -0, and no control
// character below U+0020 in a string or a key. Encoders write those
// differently. NaN and Infinity are not JSON and never reach here.
func hasOnlyPortableValues(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, member := range v {
			if !hasOnlyPortableValues(key) || !hasOnlyPortableValues(member) {
				return false
			}
		}
	case []any:
		for _, item := range v {
			if !hasOnlyPortableValues(item) {
				return false
			}
		}
	case string:
		for _, character := range v {
			if character < 0x20 {
				return false
			}
		}
	case json.Number:
		return v.String() != "-0" && !strings.ContainsAny(v.String(), ".eE")
	}
	return true
}

// verifyTeamCertificateObjectSignature verifies the signature over the
// certificate's canonical JSON without the signature, under the team key.
func verifyTeamCertificateObjectSignature(certificate map[string]any, teamDIDKey string) error {
	if _, err := ExtractPublicKey(teamDIDKey); err != nil {
		return &TeamCertificateError{Reason: "invalid_team_key"}
	}
	unsigned := make(map[string]any, len(certificate))
	for name, value := range certificate {
		if name != "signature" {
			unsigned[name] = value
		}
	}
	payload, err := CanonicalJSONValue(unsigned)
	if err != nil {
		return &TeamCertificateError{Reason: "bad_signature"}
	}
	signature, err := base64.RawStdEncoding.DecodeString(certificate["signature"].(string))
	if err != nil || idStrictVerify(teamDIDKey, signature, func() ([]byte, error) { return []byte(payload), nil }) != nil {
		return &TeamCertificateError{Reason: "bad_signature"}
	}
	return nil
}
