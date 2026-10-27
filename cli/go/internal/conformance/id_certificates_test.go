package conformance_test

import (
	"bytes"
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
		DIDKey string `json:"did_key"`
	} `json:"keys"`
	Presentation struct {
		Bundle map[string]any `json:"bundle"`
		Header string         `json:"header"`
	} `json:"presentation"`
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
