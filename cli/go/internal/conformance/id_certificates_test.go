package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	awid "github.com/awebai/aw/awid"
)

type idCertificateVectors struct {
	Certificates map[string]struct {
		Signed          map[string]any `json:"signed"`
		SigningBytesHex string         `json:"signing_bytes_hex"`
		CertificateID   string         `json:"certificate_id"`
	} `json:"certificates"`
	Keys map[string]struct {
		DIDKey  string `json:"did_key"`
		SeedHex string `json:"seed_hex"`
	} `json:"keys"`
	Presentation struct {
		Bundle map[string]any `json:"bundle"`
		Header string         `json:"header"`
	} `json:"presentation"`
	VerificationCases []struct {
		Name  string   `json:"name"`
		Chain []string `json:"chain"`
	} `json:"verification_cases"`
	Ed25519Verification struct {
		Cases []struct {
			Name         string `json:"name"`
			PublicKeyHex string `json:"public_key_hex"`
			MessageHex   string `json:"message_hex"`
			SignatureHex string `json:"signature_hex"`
			Expected     struct {
				Accepted bool   `json:"accepted"`
				Reason   string `json:"reason"`
			} `json:"expected"`
		} `json:"cases"`
	} `json:"ed25519_verification"`
	RawWireRefusals []struct {
		Name         string `json:"name"`
		RawUTF8      string `json:"raw_utf8"`
		Header       string `json:"header"`
		HeaderRepeat *struct {
			Character string `json:"character"`
			Count     int    `json:"count"`
		} `json:"header_repeat"`
		DecodedRepeat *struct {
			Character string `json:"character"`
			Count     int    `json:"count"`
		} `json:"decoded_repeat"`
		ExpectedReason string   `json:"expected_reason"`
		AllowedReasons []string `json:"allowed_reasons"`
	} `json:"raw_wire_refusals"`
}

func loadIDCertificateVectors(t *testing.T) idCertificateVectors {
	t.Helper()
	var v idCertificateVectors
	decoder := json.NewDecoder(bytes.NewReader(readRootVector(t, "id-certificates-v1.json")))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestIDCertificateFrozenSigningBytesAndDigest(t *testing.T) {
	v := loadIDCertificateVectors(t)
	for name, c := range v.Certificates {
		t.Run(name, func(t *testing.T) {
			certificate := c.Signed["certificate"].(map[string]any)
			got, err := awid.IDCertificateSigningBytes(certificate)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != c.SigningBytesHex {
				t.Fatal("signing bytes differ from frozen vector")
			}
			digest, err := awid.IDCertificateID(certificate)
			if err != nil {
				t.Fatal(err)
			}
			if digest != c.CertificateID {
				t.Fatalf("digest=%s, want %s", digest, c.CertificateID)
			}
		})
	}
}

func TestIDCertificateFrozenHeaderRoundTrip(t *testing.T) {
	c := loadIDCertificateVectors(t).Presentation
	got, err := awid.EncodeIDChainHeader(c.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got != c.Header {
		t.Fatal("header differs from frozen vector")
	}
	decoded, err := awid.DecodeIDChainHeader(c.Header)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, c.Bundle) {
		t.Fatal("decoded bundle differs")
	}
}

func TestIDCertificateRawHeaderRefusals(t *testing.T) {
	for _, c := range loadIDCertificateVectors(t).RawWireRefusals {
		t.Run(c.Name, func(t *testing.T) {
			header := c.Header
			switch {
			case c.HeaderRepeat != nil:
				header = strings.Repeat(c.HeaderRepeat.Character, c.HeaderRepeat.Count)
			case c.DecodedRepeat != nil:
				header = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(c.DecodedRepeat.Character, c.DecodedRepeat.Count)))
			case header == "":
				header = base64.RawURLEncoding.EncodeToString([]byte(c.RawUTF8))
			}
			_, err := awid.DecodeIDChainHeader(header)
			got := awid.IDCertificateErrorCode(err)
			allowed := c.AllowedReasons
			if len(allowed) == 0 {
				allowed = []string{c.ExpectedReason}
			}
			for _, reason := range allowed {
				if got == reason {
					return
				}
			}
			t.Fatalf("refusal=%q (%v), want one of %v", got, err, allowed)
		})
	}
}

func TestIDCertificateHumanRequiresStableIDAtShapeTime(t *testing.T) {
	c := loadIDCertificateVectors(t).Certificates["did-key-human"].Signed
	issuer := c["certificate"].(map[string]any)["issuer_key"].(string)
	if got := awid.IDCertificateErrorCode(awid.VerifyIDCertificate(c, issuer)); got != "invalid_shape" {
		t.Fatalf("refusal=%q, want invalid_shape", got)
	}
}

func TestIDCertificateChecksIndependentIssuer(t *testing.T) {
	v := loadIDCertificateVectors(t)
	signed := v.Certificates["alice"].Signed
	if err := awid.VerifyIDCertificate(signed, v.Keys["root"].DIDKey); err != nil {
		t.Fatal(err)
	}
	if got := awid.IDCertificateErrorCode(awid.VerifyIDCertificate(signed, v.Keys["bob"].DIDKey)); got != "invalid_signature" {
		t.Fatalf("refusal=%q, want invalid_signature", got)
	}
}

func TestIDCertificateCanonicalUTF8DoesNotRewriteLiteralEscapes(t *testing.T) {
	got, err := awid.IDCertificateSigningBytes(map[string]any{"text": "\u2028", "literal": `\u2028`})
	if err != nil {
		t.Fatal(err)
	}
	want := awid.IDCertificatePrefix + "{\"literal\":\"\\\\u2028\",\"text\":\"\u2028\"}"
	if string(got) != want {
		t.Fatalf("canonical UTF8 bytes=%q, want %q", got, want)
	}
}

func TestIDCertificateStrictEd25519Probes(t *testing.T) {
	v := loadIDCertificateVectors(t)
	for _, q := range v.Ed25519Verification.Cases {
		t.Run(q.Name, func(t *testing.T) {
			c := map[string]any{}
			for k, x := range v.Certificates["alice"].Signed["certificate"].(map[string]any) {
				c[k] = x
			}
			original, e := awid.IDCertificateSigningBytes(c)
			if e != nil {
				t.Fatal(e)
			}
			if hex.EncodeToString(original) != q.MessageHex {
				t.Fatal("probe message differs from frozen certificate")
			}
			public, e := hex.DecodeString(q.PublicKeyHex)
			if e != nil {
				t.Fatal(e)
			}
			signature, e := hex.DecodeString(q.SignatureHex)
			if e != nil {
				t.Fatal(e)
			}
			issuer := awid.ComputeDIDKey(public)
			c["issuer_key"] = issuer
			signed := map[string]any{"certificate": c, "signature": base64.RawURLEncoding.EncodeToString(signature)}
			err := awid.VerifyIDCertificate(signed, issuer)
			if q.Expected.Accepted {
				if err != nil {
					t.Fatal(err)
				}
			} else if got := awid.IDCertificateErrorCode(err); got != q.Expected.Reason {
				t.Fatalf("refusal=%q, want %s", got, q.Expected.Reason)
			}
		})
	}
}
func TestIDCertificateDepthCapOnSignedChain(t *testing.T) {
	v := loadIDCertificateVectors(t)
	for _, q := range v.VerificationCases {
		if q.Name != "maximum-depth-eight" && q.Name != "depth-nine-refuses" {
			continue
		}
		t.Run(q.Name, func(t *testing.T) {
			certs := []any{}
			for _, n := range q.Chain {
				certs = append(certs, v.Certificates[n].Signed)
			}
			bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certs}
			raw, e := json.Marshal(bundle)
			if e != nil {
				t.Fatal(e)
			}
			if len(raw) >= awid.IDChainMaxBytes {
				t.Fatal("not exercising depth independently of byte cap")
			}
			header := base64.RawURLEncoding.EncodeToString(raw)
			_, decodeErr := awid.DecodeIDChainHeader(header)
			_, encodeErr := awid.EncodeIDChainHeader(bundle)
			for _, err := range []error{decodeErr, encodeErr} {
				if q.Name == "maximum-depth-eight" {
					if err != nil {
						t.Fatal(err)
					}
				} else if awid.IDCertificateErrorCode(err) != "depth_exceeded" {
					t.Fatalf("want depth_exceeded, got %v", err)
				}
			}
		})
	}
}
func TestIDCertificateClaimedIssuerMustMatchSelectedSigner(t *testing.T) {
	v := loadIDCertificateVectors(t)
	c := v.Certificates["alice"].Signed["certificate"].(map[string]any)
	msg, e := awid.IDCertificateSigningBytes(c)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := hex.DecodeString(v.Keys["bob"].SeedHex)
	if e != nil {
		t.Fatal(e)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)
	signed := map[string]any{"certificate": c, "signature": base64.RawURLEncoding.EncodeToString(sig)}
	if got := awid.IDCertificateErrorCode(awid.VerifyIDCertificate(signed, v.Keys["bob"].DIDKey)); got != "invalid_signature" {
		t.Fatalf("refusal=%q, want invalid_signature", got)
	}
}
func TestIDCertificateYearZeroRefusesAtShape(t *testing.T) {
	v := loadIDCertificateVectors(t)
	c := v.Certificates["alice"].Signed["certificate"].(map[string]any)
	c["issued_at"] = "0000-01-01T00:00:00Z"
	if got := awid.IDCertificateErrorCode(awid.VerifyIDCertificate(v.Certificates["alice"].Signed, v.Keys["root"].DIDKey)); got != "invalid_shape" {
		t.Fatalf("refusal=%q, want invalid_shape", got)
	}
}
