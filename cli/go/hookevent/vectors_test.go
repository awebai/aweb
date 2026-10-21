package hookevent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/strictjson"
)

const (
	envelopeVectorPath = "../../../docs/vectors/hook-event-envelope-v1.json"
	deliveryVectorPath = "../../../docs/vectors/hook-delivery-credential-v1.json"
	catalogVectorPath  = "../../../docs/vectors/hook-catalog-v1.json"
)

// HOOKEVENT_WRITE_VECTORS=1 rewrites the two vectors from the definitions in
// vector_cases_test.go. A normal run regenerates every positive case and
// requires the committed bytes to match.
func TestWriteVectors(t *testing.T) {
	if os.Getenv("HOOKEVENT_WRITE_VECTORS") != "1" {
		t.Skip("set HOOKEVENT_WRITE_VECTORS=1 to rewrite the hook vectors")
	}
	for path, document := range map[string]any{
		envelopeVectorPath: buildEnvelopeVector(t),
		deliveryVectorPath: buildDeliveryVector(t),
	} {
		data, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readVector(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

func TestEnvelopeVectorRegeneratesByteForByte(t *testing.T) {
	var committed, rebuilt map[string]any
	readVector(t, envelopeVectorPath, &committed)
	data, err := json.Marshal(buildEnvelopeVector(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rebuilt); err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, committed, rebuilt)
}

func TestDeliveryVectorRegeneratesByteForByte(t *testing.T) {
	var committed, rebuilt map[string]any
	readVector(t, deliveryVectorPath, &committed)
	data, err := json.Marshal(buildDeliveryVector(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rebuilt); err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, committed, rebuilt)
}

func assertSameJSON(t *testing.T, committed, rebuilt map[string]any) {
	t.Helper()
	a, _ := json.Marshal(committed)
	b, _ := json.Marshal(rebuilt)
	if string(a) != string(b) {
		t.Fatalf("committed vector differs from the regenerated one; rerun with HOOKEVENT_WRITE_VECTORS=1 only for a reviewed change")
	}
}

type envelopeVector struct {
	Positive []struct {
		Name          string         `json:"name"`
		SeedHex       string         `json:"seed_hex"`
		Envelope      map[string]any `json:"envelope"`
		SigningB64URL string         `json:"signing_bytes_b64url"`
		Signature     string         `json:"signature_b64"`
	} `json:"positive_cases"`
	Negative []struct {
		Name          string `json:"name"`
		SigningB64URL string `json:"signing_bytes_b64url"`
		Signature     string `json:"signature_b64"`
		TeamID        string `json:"verify_team_id"`
		Layer         string `json:"layer"`
		Error         string `json:"error"`
	} `json:"negative_cases"`
}

func TestEnvelopeVectorCases(t *testing.T) {
	var v envelopeVector
	readVector(t, envelopeVectorPath, &v)
	if len(v.Positive) == 0 || len(v.Negative) == 0 {
		t.Fatal("vector has no cases")
	}
	for _, c := range v.Positive {
		t.Run(c.Name, func(t *testing.T) {
			seed, _ := hex.DecodeString(c.SeedHex)
			key := ed25519.NewKeyFromSeed(seed)
			signing, signature, err := Sign(key, toStrictValues(c.Envelope))
			if err != nil {
				t.Fatal(err)
			}
			if got := base64.RawURLEncoding.EncodeToString(signing); got != c.SigningB64URL {
				t.Fatalf("signing bytes differ:\n got  %s\n want %s", got, c.SigningB64URL)
			}
			if signature != c.Signature {
				t.Fatalf("signature differs")
			}
			if _, err := Verify(signing, signature, VerifyOptions{TeamID: c.Envelope["team_id"].(string)}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, c := range v.Negative {
		t.Run(c.Name, func(t *testing.T) {
			signing, err := base64.RawURLEncoding.DecodeString(c.SigningB64URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(signing, c.Signature, VerifyOptions{TeamID: c.TeamID})
			switch c.Layer {
			case "envelope":
				if strictjson.Code(err) != c.Error {
					t.Fatalf("got %v, want %s", err, c.Error)
				}
			case "catalog":
				if err != nil {
					t.Fatalf("a catalog-layer fault must pass the envelope layer: %v", err)
				}
			default:
				t.Fatalf("unknown layer %q", c.Layer)
			}
		})
	}
}

type deliveryVector struct {
	Positive []struct {
		Name          string            `json:"name"`
		SeedHex       string            `json:"seed_hex"`
		Target        string            `json:"target"`
		BindingID     string            `json:"binding_id"`
		Timestamp     string            `json:"timestamp"`
		EventSigning  string            `json:"event_signing_bytes_b64url"`
		EventSig      string            `json:"event_signature_b64"`
		Headers       map[string]string `json:"headers"`
		Body          string            `json:"body"`
		SignedPayload string            `json:"canonical_signed_payload"`
		Certificate   string            `json:"certificate"`
		Receive       receiveCase       `json:"receive"`
	} `json:"positive_cases"`
	Negative []struct {
		Name    string            `json:"name"`
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Receive receiveCase       `json:"receive"`
		Error   string            `json:"error"`
	} `json:"negative_cases"`
}

type receiveCase struct {
	Audience   string `json:"audience"`
	BindingID  string `json:"binding_id"`
	TeamKeyDID string `json:"team_key_did"`
	Now        string `json:"now"`
}

func (r receiveCase) options(t *testing.T) ReceiveOptions {
	now, err := time.Parse(deliveryTimeLayout, r.Now)
	if err != nil {
		t.Fatal(err)
	}
	return ReceiveOptions{Audience: r.Audience, BindingID: r.BindingID, TeamKeyDID: r.TeamKeyDID, Now: now}
}

func TestDeliveryVectorCases(t *testing.T) {
	var v deliveryVector
	readVector(t, deliveryVectorPath, &v)
	if len(v.Positive) == 0 || len(v.Negative) == 0 {
		t.Fatal("vector has no cases")
	}
	for _, c := range v.Positive {
		t.Run(c.Name, func(t *testing.T) {
			seed, _ := hex.DecodeString(c.SeedHex)
			target, _ := url.Parse(c.Target)
			stamp, _ := time.Parse(deliveryTimeLayout, c.Timestamp)
			signing, _ := base64.RawURLEncoding.DecodeString(c.EventSigning)
			var cert *awid.TeamCertificate
			if c.Certificate != "" {
				var err error
				cert, err = awid.DecodeTeamCertificateHeader(c.Certificate)
				if err != nil {
					t.Fatal(err)
				}
			}
			d, err := SignDelivery(ed25519.NewKeyFromSeed(seed), "POST", target, c.BindingID, signing, c.EventSig, cert, stamp)
			if err != nil {
				t.Fatal(err)
			}
			if string(d.Body) != c.Body || string(d.SignedPayload) != c.SignedPayload {
				t.Fatalf("delivery bytes differ")
			}
			for name, value := range c.Headers {
				if d.Headers[name] != value {
					t.Fatalf("header %s differs", name)
				}
			}
			if _, err := VerifyDelivery("POST", d.Path, d.Headers, d.Body, c.Receive.options(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, c := range v.Negative {
		t.Run(c.Name, func(t *testing.T) {
			_, err := VerifyDelivery(c.Method, c.Path, c.Headers, []byte(c.Body), c.Receive.options(t))
			if strictjson.Code(err) != c.Error {
				t.Fatalf("got %v, want %s", err, c.Error)
			}
		})
	}
}

func TestHookTableMatchesCatalogVector(t *testing.T) {
	var catalog struct {
		Catalog struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
		} `json:"catalog"`
		Hooks map[string]struct {
			Class     string   `json:"class"`
			Producers []string `json:"producer_kinds"`
		} `json:"hooks"`
	}
	readVector(t, catalogVectorPath, &catalog)
	if catalog.Catalog.ID != CatalogID || catalog.Catalog.Version != CatalogVersion {
		t.Fatalf("catalog %s v%d", catalog.Catalog.ID, catalog.Catalog.Version)
	}
	if len(catalog.Hooks) != len(Hooks) {
		t.Fatalf("catalog has %d hooks, package has %d", len(catalog.Hooks), len(Hooks))
	}
	for name, hook := range catalog.Hooks {
		class, producers, ok := HookClass(name)
		if !ok || class != hook.Class || strings.Join(producers, ",") != strings.Join(hook.Producers, ",") {
			t.Fatalf("hook %s differs from the catalog", name)
		}
	}
}

// toStrictValues converts encoding/json's float64 numbers into the int64
// values the strict reader produces.
func toStrictValues(value map[string]any) map[string]any {
	data, _ := json.Marshal(value)
	parsed, err := strictjson.ParseStrict(data)
	if err != nil {
		panic(err)
	}
	return parsed.(map[string]any)
}

func didKeyOf(key ed25519.PrivateKey) string {
	return awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
}

// A client builds post-command-hook payloads in Go, and the catalog reader
// lives in Python. This checks the client's payloads against the catalog
// vector's own post-command-hook allowlist, so the two cannot drift.
func TestClientPayloadsSatisfyTheCatalog(t *testing.T) {
	type fieldSpec struct {
		Type       string   `json:"type"`
		Enum       []string `json:"enum"`
		ListOf     string   `json:"list_of"`
		ListOfEnum []string `json:"list_of_enum"`
		MinItems   int      `json:"min_items"`
		MaxItems   int      `json:"max_items"`
		Required   bool     `json:"required"`
	}
	var catalog struct {
		Types map[string]struct {
			Kind    string `json:"kind"`
			Pattern string `json:"pattern"`
			Min     int64  `json:"min"`
			Max     int64  `json:"max"`
		} `json:"types"`
		Hooks map[string]struct {
			Fields         map[string]fieldSpec `json:"fields"`
			CommandClasses map[string][]string  `json:"command_classes"`
		} `json:"hooks"`
	}
	readVector(t, catalogVectorPath, &catalog)
	hook := catalog.Hooks["post-command-hook"]
	accepts := func(typeName string, value any) bool {
		spec := catalog.Types[typeName]
		switch spec.Kind {
		case "string":
			s, ok := value.(string)
			return ok && regexp.MustCompile(spec.Pattern).MatchString(s)
		case "integer":
			n, ok := value.(int64)
			return ok && n >= spec.Min && n <= spec.Max
		}
		return false
	}
	payload := clientEnvelope()["payload"].(map[string]any)
	for name, value := range payload {
		spec, known := hook.Fields[name]
		if !known {
			t.Fatalf("payload field %s is not in the catalog", name)
		}
		switch {
		case spec.Type != "":
			if !accepts(spec.Type, value) {
				t.Fatalf("%s=%v is not a %s", name, value, spec.Type)
			}
		case spec.Enum != nil:
			if !contains(spec.Enum, value.(string)) {
				t.Fatalf("%s=%v is not in its enum", name, value)
			}
		default:
			items := value.([]any)
			if len(items) < spec.MinItems || len(items) > spec.MaxItems {
				t.Fatalf("%s has %d items", name, len(items))
			}
			for _, item := range items {
				if spec.ListOf != "" && !accepts(spec.ListOf, item) || spec.ListOfEnum != nil && !contains(spec.ListOfEnum, item.(string)) {
					t.Fatalf("%s item %v is refused", name, item)
				}
			}
		}
	}
	for name, spec := range hook.Fields {
		if _, present := payload[name]; spec.Required && !present {
			t.Fatalf("payload lacks required %s", name)
		}
	}
	for _, effect := range payload["local_effects"].([]any) {
		if !contains(hook.CommandClasses[payload["command_class"].(string)], effect.(string)) {
			t.Fatalf("effect %v is outside its command class", effect)
		}
	}
}
