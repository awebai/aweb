package hookevent

import (
	"net/url"
	"testing"
	"time"

	"github.com/awebai/aw/strictjson"
)

func TestVerifiersFailClosedWithoutTheirOwnFacts(t *testing.T) {
	signing, signature, err := Sign(keyFrom(coreSeed), coreEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signing, signature, VerifyOptions{}); strictjson.Code(err) != "verifier_misconfigured" {
		t.Fatalf("empty team: got %v", err)
	}
	target, _ := url.Parse(logsTarget)
	now, _ := time.Parse(deliveryTimeLayout, receivedAt)
	stamp, _ := time.Parse(deliveryTimeLayout, signedAt)
	d, err := SignDelivery(keyFrom(coreSeed), "POST", target, bindingID, signing, signature, nil, stamp)
	if err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string]ReceiveOptions{
		"empty audience": {BindingID: bindingID, Now: now},
		"empty binding":  {Audience: logsOrigin, Now: now},
	} {
		if _, err := VerifyDelivery("POST", d.Path, d.Headers, d.Body, opts); strictjson.Code(err) != "verifier_misconfigured" {
			t.Fatalf("%s: got %v", name, err)
		}
	}

	clientSigning, clientSignature, err := Sign(keyFrom(clientSeed), clientEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	cert := fixtureCertificate(t, keyFrom(teamSeed), teamID, "c_77", didKeyOf(keyFrom(clientSeed)))
	c, err := SignDelivery(keyFrom(clientSeed), "POST", target, bindingID, clientSigning, clientSignature, cert, stamp)
	if err != nil {
		t.Fatal(err)
	}
	opts := ReceiveOptions{Audience: logsOrigin, BindingID: bindingID, Now: now}
	if _, err := VerifyDelivery("POST", c.Path, c.Headers, c.Body, opts); strictjson.Code(err) != "verifier_misconfigured" {
		t.Fatalf("client delivery without a team key: got %v", err)
	}
}

func TestSignDeliveryCarriesACertificateOnlyForAClient(t *testing.T) {
	target, _ := url.Parse(logsTarget)
	stamp, _ := time.Parse(deliveryTimeLayout, signedAt)
	clientSigning, clientSignature, _ := Sign(keyFrom(clientSeed), clientEnvelope())
	if _, err := SignDelivery(keyFrom(clientSeed), "POST", target, bindingID, clientSigning, clientSignature, nil, stamp); strictjson.Code(err) != "certificate_missing" {
		t.Fatalf("client without certificate: got %v", err)
	}
	other := fixtureCertificate(t, keyFrom(teamSeed), teamID, "c_77", didKeyOf(keyFrom(memberSeed)))
	if _, err := SignDelivery(keyFrom(clientSeed), "POST", target, bindingID, clientSigning, clientSignature, other, stamp); strictjson.Code(err) != "certificate_mismatch" {
		t.Fatalf("client with another member's certificate: got %v", err)
	}
	coreSigning, coreSignature, _ := Sign(keyFrom(coreSeed), coreEnvelope())
	cert := fixtureCertificate(t, keyFrom(teamSeed), teamID, "c_77", didKeyOf(keyFrom(clientSeed)))
	if _, err := SignDelivery(keyFrom(coreSeed), "POST", target, bindingID, coreSigning, coreSignature, cert, stamp); strictjson.Code(err) != "invalid_value" {
		t.Fatalf("server with a certificate: got %v", err)
	}
}
