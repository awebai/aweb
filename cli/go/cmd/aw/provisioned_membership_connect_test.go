package main

import (
	"strings"
	"testing"
)

func TestConnectRejectsUnknownPublicationPolicyBeforeTransport(t *testing.T) {
	_, err := initCertificateConnectWithOptions(t.TempDir(), "http://127.0.0.1:1", certificateConnectOptions{EncryptionPublication: encryptionPublicationPolicy(255)})
	if err == nil || !strings.Contains(err.Error(), "publication policy is unknown") {
		t.Fatalf("unknown policy reached admission: %v", err)
	}
}
