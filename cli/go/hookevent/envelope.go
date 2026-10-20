package hookevent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
	"sort"

	"github.com/awebai/aw/awid"
)

// EnvelopePrefix domain-separates hook event signatures from every other
// signed object in the family.
const EnvelopePrefix = "aweb.hook-event/1\n"

// CatalogID and CatalogVersion name the only catalog this package knows.
const (
	CatalogID      = "aweb.hooks"
	CatalogVersion = 1
)

type hookSpec struct {
	class     string
	producers []string
}

// Hooks is the aweb.hooks v1 hook table this package enforces: each hook's
// firing class and the producer kinds that may sign it. The conformance test
// checks it against the catalog vector.
var Hooks = map[string]hookSpec{
	"post-secret-use-hook":       {class: "server", producers: []string{"app"}},
	"post-governance-hook":       {class: "server", producers: []string{"app"}},
	"post-manifest-command-hook": {class: "server", producers: []string{"app"}},
	"post-mutation-hook":         {class: "server", producers: []string{"core"}},
	"post-command-hook":          {class: "client", producers: []string{"client"}},
}

// HookClass returns a known hook's firing class and producer kinds.
func HookClass(hook string) (class string, producers []string, ok bool) {
	spec, ok := Hooks[hook]
	return spec.class, spec.producers, ok
}

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	traceIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	teamIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	originPattern    = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	kidPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	didKeyPattern    = regexp.MustCompile(`^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$`)
	didAWPattern     = regexp.MustCompile(`^did:aw:[1-9A-HJ-NP-Za-km-z]{20,32}$`)
	appIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	certIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	aliasPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	timePattern      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
	attestationShape = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

const (
	maxAttestations     = 4
	maxAttestationBytes = 8192
)

var authorityModes = []string{"team_cert", "identity_grant", "app_key", "link_capability", "owner_act", "system"}
var resultStatuses = []string{"success", "denied", "failed", "outcome_unknown"}

// Envelope is a verified hook event.
type Envelope struct {
	Fields         map[string]any
	Hook           string
	EventID        string
	TeamID         string
	ProducerKind   string
	ProducerDIDKey string
	ProducerKID    string
	// Producer is the producer's identity as a delivery credential names it:
	// "core", "app:<app_id>" or "client:<certificate_id>".
	Producer string
}

// SigningBytes validates an envelope and returns the bytes its producer
// signs: the prefix followed by the envelope's canonical JSON.
func SigningBytes(envelope map[string]any) ([]byte, error) {
	canonical, err := Canonical(envelope)
	if err != nil {
		return nil, err
	}
	parsed, err := parseCanonicalObject(canonical)
	if err != nil {
		return nil, err
	}
	if _, err := checkEnvelope(parsed); err != nil {
		return nil, err
	}
	return append([]byte(EnvelopePrefix), canonical...), nil
}

// Sign returns an envelope's signing bytes and its detached Ed25519
// signature (raw standard base64, no padding). The key must be the
// envelope's producer key.
func Sign(key ed25519.PrivateKey, envelope map[string]any) ([]byte, string, error) {
	signing, err := SigningBytes(envelope)
	if err != nil {
		return nil, "", err
	}
	producer, _ := envelope["producer"].(map[string]any)
	if didKey, _ := producer["did_key"].(string); didKey != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
		return nil, "", refuse("signer_mismatch", "the key is not the producer's did_key")
	}
	return signing, base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, signing)), nil
}

// VerifyOptions are the facts a verifier already holds about the event.
type VerifyOptions struct {
	// TeamID, when set, is the team the event must belong to.
	TeamID string
}

// Verify checks signing bytes and a signature, in the order the contract
// states, and returns the verified envelope or the first refusal.
func Verify(signing []byte, signature string, opts VerifyOptions) (*Envelope, error) {
	if !bytes.HasPrefix(signing, []byte(EnvelopePrefix)) {
		return nil, refuse("wrong_prefix", "signing bytes do not start with %q", EnvelopePrefix)
	}
	fields, err := parseCanonicalObject(signing[len(EnvelopePrefix):])
	if err != nil {
		return nil, err
	}
	env, err := checkEnvelope(fields)
	if err != nil {
		return nil, err
	}
	if opts.TeamID != "" && env.TeamID != opts.TeamID {
		return nil, refuse("team_mismatch", "event team %s, expected %s", env.TeamID, opts.TeamID)
	}
	if err := verifySignature(env.ProducerDIDKey, signing, signature); err != nil {
		return nil, err
	}
	return env, nil
}

func verifySignature(didKey string, message []byte, signature string) error {
	public, err := awid.ExtractPublicKey(didKey)
	if err != nil {
		return refuse("bad_signature", "did:key does not decode")
	}
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return refuse("bad_signature", "signature is not 64 bytes of unpadded standard base64")
	}
	if !ed25519.Verify(public, message, sig) {
		return refuse("bad_signature", "signature does not verify")
	}
	return nil
}

func checkEnvelope(f map[string]any) (*Envelope, error) {
	if err := checkKeys(f, "", []string{
		"v", "type", "catalog", "hook", "event_id", "trace", "team_id", "producer",
		"actor", "occurred_at", "fired_at", "result_status", "payload",
	}, nil); err != nil {
		return nil, err
	}
	if v, ok := f["v"].(int64); !ok || v != 1 {
		return nil, refuse("invalid_value", "v")
	}
	if f["type"] != "aweb.hook-event" {
		return nil, refuse("invalid_value", "type")
	}

	catalog, err := object(f, "catalog")
	if err != nil {
		return nil, err
	}
	if err := checkKeys(catalog, "catalog.", []string{"id", "version"}, nil); err != nil {
		return nil, err
	}
	if version, ok := catalog["version"].(int64); catalog["id"] != CatalogID || !ok || version != CatalogVersion {
		return nil, refuse("unknown_catalog", "%v version %v", catalog["id"], catalog["version"])
	}
	hook, _ := f["hook"].(string)
	spec, known := Hooks[hook]
	if !known {
		return nil, refuse("unknown_hook", "%v", f["hook"])
	}

	if err := match(f, "event_id", uuidPattern); err != nil {
		return nil, err
	}
	trace, err := object(f, "trace")
	if err != nil {
		return nil, err
	}
	if err := checkKeys(trace, "trace.", []string{"id", "origin"}, nil); err != nil {
		return nil, err
	}
	if id, _ := trace["id"].(string); !traceIDPattern.MatchString(id) || id == "00000000000000000000000000000000" {
		return nil, refuse("invalid_value", "trace.id")
	}
	if err := oneOf(trace, "origin", "trace.", []string{"signed_request", "producer"}); err != nil {
		return nil, err
	}
	if err := match(f, "team_id", teamIDPattern); err != nil {
		return nil, err
	}

	env := &Envelope{Fields: f, Hook: hook, EventID: f["event_id"].(string), TeamID: f["team_id"].(string)}
	producer, err := object(f, "producer")
	if err != nil {
		return nil, err
	}
	if err := checkProducer(producer, env); err != nil {
		return nil, err
	}
	actor, err := object(f, "actor")
	if err != nil {
		return nil, err
	}
	if err := checkActor(actor); err != nil {
		return nil, err
	}

	for _, name := range []string{"occurred_at", "fired_at"} {
		if err := match(f, name, timePattern); err != nil {
			return nil, err
		}
	}
	if f["fired_at"].(string) < f["occurred_at"].(string) {
		return nil, refuse("invalid_value", "fired_at precedes occurred_at")
	}
	if err := oneOf(f, "result_status", "", resultStatuses); err != nil {
		return nil, err
	}
	if err := checkPayloadShape(f["payload"]); err != nil {
		return nil, err
	}

	if !contains(spec.producers, env.ProducerKind) {
		return nil, refuse("producer_not_allowed", "%s may not sign %s", env.ProducerKind, hook)
	}
	if env.ProducerKind == "client" {
		if actor["did_key"] != producer["did_key"] || actor["certificate_id"] != producer["certificate_id"] {
			return nil, refuse("actor_not_signer", "a client event's actor is its signer")
		}
	}
	return env, nil
}

func checkProducer(p map[string]any, env *Envelope) error {
	kind, _ := p["kind"].(string)
	switch kind {
	case "core":
		if err := checkKeys(p, "producer.", []string{"kind", "origin", "kid", "did_key", "seq"}, nil); err != nil {
			return err
		}
		env.Producer = "core"
	case "app":
		if err := checkKeys(p, "producer.", []string{
			"kind", "origin", "app_id", "installation_id", "generation", "kid", "did_key", "seq",
		}, nil); err != nil {
			return err
		}
		if err := match(p, "app_id", appIDPattern); err != nil {
			return err
		}
		if err := match(p, "installation_id", uuidPattern); err != nil {
			return err
		}
		if err := positive(p, "generation"); err != nil {
			return err
		}
		env.Producer = "app:" + p["app_id"].(string)
	case "client":
		if err := checkKeys(p, "producer.", []string{"kind", "did_key", "certificate_id"}, nil); err != nil {
			return err
		}
		if err := match(p, "certificate_id", certIDPattern); err != nil {
			return err
		}
		env.Producer = "client:" + p["certificate_id"].(string)
	default:
		return refuse("invalid_value", "producer.kind")
	}
	if kind != "client" {
		if err := match(p, "origin", originPattern); err != nil {
			return err
		}
		if err := match(p, "kid", kidPattern); err != nil {
			return err
		}
		if err := positive(p, "seq"); err != nil {
			return err
		}
		env.ProducerKID = p["kid"].(string)
	}
	if err := match(p, "did_key", didKeyPattern); err != nil {
		return err
	}
	env.ProducerKind = kind
	env.ProducerDIDKey = p["did_key"].(string)
	return nil
}

func checkActor(a map[string]any) error {
	if err := checkKeys(a, "actor.", []string{"authority_mode", "attestations"},
		[]string{"did_key", "did_aw", "certificate_id", "alias", "grant_id"}); err != nil {
		return err
	}
	if err := oneOf(a, "authority_mode", "actor.", authorityModes); err != nil {
		return err
	}
	mode := a["authority_mode"].(string)
	identity := []string{"did_key", "did_aw", "certificate_id", "alias", "grant_id"}
	if mode == "system" {
		for _, name := range identity {
			if _, present := a[name]; present {
				return refuse("invalid_value", "actor.%s: a system actor has no identity", name)
			}
		}
	} else if _, present := a["did_key"]; !present {
		return refuse("missing_field", "actor.did_key")
	}
	_, hasGrant := a["grant_id"]
	if (mode == "identity_grant") != hasGrant {
		return refuse("invalid_value", "actor.grant_id belongs to identity_grant authority only")
	}
	checks := map[string]*regexp.Regexp{
		"did_key": didKeyPattern, "did_aw": didAWPattern, "certificate_id": certIDPattern,
		"alias": aliasPattern, "grant_id": uuidPattern,
	}
	for _, name := range sortedKeys(checks) {
		if _, present := a[name]; present {
			if err := matchPrefixed(a, name, "actor.", checks[name]); err != nil {
				return err
			}
		}
	}
	list, ok := a["attestations"].([]any)
	if !ok || len(list) > maxAttestations {
		return refuse("invalid_value", "actor.attestations")
	}
	for _, item := range list {
		s, ok := item.(string)
		if !ok || len(s) > maxAttestationBytes || !attestationShape.MatchString(s) {
			return refuse("invalid_value", "actor.attestations")
		}
	}
	return nil
}

// checkPayloadShape enforces the shape every catalog payload shares: a flat
// object of strings, integers, booleans and lists of strings. The catalog's
// own allowlist is checked by the catalog reader.
func checkPayloadShape(value any) error {
	payload, ok := value.(map[string]any)
	if !ok {
		return refuse("invalid_value", "payload is not an object")
	}
	for _, name := range sortedKeys(payload) {
		switch v := payload[name].(type) {
		case string, int64, bool:
		case []any:
			for _, item := range v {
				if _, ok := item.(string); !ok {
					return refuse("invalid_value", "payload.%s", name)
				}
			}
		default:
			return refuse("invalid_value", "payload.%s", name)
		}
	}
	return nil
}

func checkKeys(object map[string]any, prefix string, required, optional []string) error {
	allowed := map[string]bool{}
	for _, name := range append(append([]string{}, required...), optional...) {
		allowed[name] = true
	}
	for _, name := range sortedKeys(object) {
		if !allowed[name] {
			return refuse("unknown_field", "%s%s", prefix, name)
		}
	}
	sorted := append([]string{}, required...)
	sort.Strings(sorted)
	for _, name := range sorted {
		if _, present := object[name]; !present {
			return refuse("missing_field", "%s%s", prefix, name)
		}
	}
	return nil
}

func object(f map[string]any, name string) (map[string]any, error) {
	value, ok := f[name].(map[string]any)
	if !ok {
		return nil, refuse("invalid_value", "%s is not an object", name)
	}
	return value, nil
}

func match(f map[string]any, name string, pattern *regexp.Regexp) error {
	return matchPrefixed(f, name, "", pattern)
}

func matchPrefixed(f map[string]any, name, prefix string, pattern *regexp.Regexp) error {
	value, ok := f[name].(string)
	if !ok || !pattern.MatchString(value) {
		return refuse("invalid_value", "%s%s", prefix, name)
	}
	return nil
}

func positive(f map[string]any, name string) error {
	value, ok := f[name].(int64)
	if !ok || value < 1 {
		return refuse("invalid_value", "%s", name)
	}
	return nil
}

func oneOf(f map[string]any, name, prefix string, options []string) error {
	value, ok := f[name].(string)
	if !ok || !contains(options, value) {
		return refuse("invalid_value", "%s%s", prefix, name)
	}
	return nil
}

func contains(options []string, value string) bool {
	for _, option := range options {
		if option == value {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
