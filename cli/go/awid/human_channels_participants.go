package awid

// Typed identity helpers only. They neither authenticate a signer nor authorize
// membership/history/admission. Guest derivation inputs remain bridge-private.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"
)

type HumanChannelsGuestDerivation struct {
	Bridge, Platform, AccountScope, AccountID, SubjectKind, Generation, SessionID string
}

func hcParticipantDTO(schema string, value any) (HumanChannelsRecord, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return HumanChannelsRecord{}, hcError("invalid", schema)
	}
	return DecodeHumanChannelsRecord(schema, raw)
}

func hcParticipantRecord(p HumanChannelsParticipant) (HumanChannelsRecord, error) {
	schema := "NativeParticipant"
	if p.Kind == "bridged" {
		schema = "BridgedParticipant"
	}
	return hcParticipantDTO(schema, p)
}

// HumanChannelsScopedParticipantKey is an exact local key, never a public address.
func HumanChannelsScopedParticipantKey(sessionID string, p HumanChannelsParticipant) ([]byte, error) {
	if _, err := hcParticipantDTO("PresenceScope", map[string]any{"kind": "session", "session_id": sessionID}); err != nil {
		return nil, err
	}
	ref, err := hcParticipantRecord(p)
	if err != nil {
		return nil, err
	}
	return StrictCanonicalJSON(map[string]any{"session_id": sessionID, "participant": ref.Value})
}

// DeriveHumanChannelsGuestReference shares one bridge-held key/generation across
// intake bots. It never grants admission or restores continuity after key loss.
func DeriveHumanChannelsGuestReference(key []byte, c HumanChannelsGuestDerivation) (HumanChannelsParticipant, error) {
	bad := HumanChannelsParticipant{}
	if len(key) < 32 {
		return bad, hcError("invalid", "subject derivation key")
	}
	if _, err := HumanChannelsScopedParticipantKey(c.SessionID, HumanChannelsParticipant{Kind: "bridged", Bridge: c.Bridge, Subject: "validation"}); err != nil {
		return bad, err
	}
	if !hcPatterns["platform_kind"].MatchString(c.Platform) || (c.SubjectKind != "human" && c.SubjectKind != "bot") {
		return bad, hcError("invalid", "private subject derivation context")
	}
	for _, v := range []string{c.AccountScope, c.AccountID, c.Generation} {
		if len(v) == 0 || len(v) > 4096 || !utf8.ValidString(v) {
			return bad, hcError("invalid", "private subject derivation context")
		}
	}
	raw, err := StrictCanonicalJSON(map[string]any{"version": "aweb-guest-subject-v1", "bridge": c.Bridge, "platform": c.Platform, "account_scope": c.AccountScope, "account_id": c.AccountID, "subject_kind": c.SubjectKind, "generation": c.Generation, "session_id": c.SessionID})
	if err != nil {
		return bad, hcError("invalid", "private subject derivation context")
	}
	digest := hmac.New(sha256.New, key)
	digest.Write(raw)
	return HumanChannelsParticipant{Kind: "bridged", Bridge: c.Bridge, Subject: base64.RawURLEncoding.EncodeToString(digest.Sum(nil))}, nil
}

// ProjectHumanChannelsSessionAuthor checks exact identity/context binding of
// facts verified by the caller. P4/P5 must independently establish current
// membership/epoch, signatures, consent, opt-out and history authorization.
// nativeTrustStatus is independently verified metadata for this exact native
// author, never inferred from confidentiality; it is unused for guests.
func ProjectHumanChannelsSessionAuthor(expectedSession string, expected HumanChannelsParticipant, group HumanChannelsGroupContext, signerPrincipal string, signerVerified bool, confidentiality, nativeTrustStatus string) (HumanChannelsRecord, error) {
	bad := HumanChannelsRecord{}
	if _, err := hcParticipantDTO("GroupContext", group); err != nil {
		return bad, err
	}
	wanted, err := HumanChannelsScopedParticipantKey(expectedSession, expected)
	if err != nil {
		return bad, err
	}
	actual, err := HumanChannelsScopedParticipantKey(group.SessionID, group.AuthorRef)
	if err != nil {
		return bad, err
	}
	if string(wanted) != string(actual) {
		return bad, hcError("forbidden", "exact session participant")
	}
	if !signerVerified {
		return bad, hcError("invalid", "unverified signer")
	}
	guest := group.AuthorRef.Kind == "bridged"
	signer := group.AuthorRef.DID
	if guest {
		signer = group.AuthorRef.Bridge
	}
	if signerPrincipal != signer {
		return bad, hcError("forbidden", "author signer binding")
	}
	if guest && confidentiality != "bridge_readable" && confidentiality != "server_readable" {
		return bad, hcError("invalid", "guest confidentiality")
	}
	if !guest && nativeTrustStatus != "verified" && nativeTrustStatus != "verified_custodial" {
		return bad, hcError("authority_unavailable", "native author status")
	}
	assurance, trust := "native", nativeTrustStatus
	if guest {
		assurance, trust = "platform_attested", "external_untrusted"
	}
	return hcParticipantDTO("AuthorProjection", map[string]any{"author": group.AuthorRef, "author_assurance": assurance, "confidentiality": confidentiality, "signer_verified": true, "trust_status": trust, "verified": !guest})
}
