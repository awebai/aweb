package awid

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestParseAWIDTXTRecordExplicitRegistry(t *testing.T) {
	t.Parallel()

	did := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	authority, err := ParseAWIDTXTRecord("awid=v1; controller="+did+"; registry=https://registry.example.com;", "_awid.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if authority.ControllerDID != did {
		t.Fatalf("ControllerDID=%q", authority.ControllerDID)
	}
	if authority.RegistryURL != "https://registry.example.com" {
		t.Fatalf("RegistryURL=%q", authority.RegistryURL)
	}
}

func TestParseAWIDTXTRecordDefaultsRegistry(t *testing.T) {
	t.Parallel()

	did := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	authority, err := ParseAWIDTXTRecord("awid=v1; controller="+did+";", "_awid.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if authority.RegistryURL != DefaultAWIDRegistryURL {
		t.Fatalf("RegistryURL=%q", authority.RegistryURL)
	}
}

func TestDiscoverAuthoritativeRegistryWalksAncestorsWithinBoundary(t *testing.T) {
	t.Parallel()

	resolver := staticTXTResolver{
		"_awid.acme.com": {"awid=v1; controller=did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd; registry=https://registry.acme.test;"},
	}

	authority, err := DiscoverAuthoritativeRegistry(context.Background(), resolver, "sub.team.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if !authority.Inherited {
		t.Fatal("expected inherited authority")
	}
	if authority.RegistryURL != "https://registry.acme.test" {
		t.Fatalf("RegistryURL=%q", authority.RegistryURL)
	}
}

func TestDiscoverAuthoritativeRegistryDefaultsWhenNoRecord(t *testing.T) {
	t.Parallel()

	authority, err := DiscoverAuthoritativeRegistry(context.Background(), staticTXTResolver{}, "missing.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if authority.RegistryURL != DefaultAWIDRegistryURL {
		t.Fatalf("RegistryURL=%q", authority.RegistryURL)
	}
}

func TestParseAWIDTXTRecordRejectsMalformedRecord(t *testing.T) {
	t.Parallel()

	_, err := ParseAWIDTXTRecord("awid=v2; controller=did:key:zbad;", "_awid.example.com")
	if err == nil {
		t.Fatal("expected malformed record error")
	}
}

func TestVerifyExactDomainAuthorityReturnsLookupErrorOnMissingRecord(t *testing.T) {
	t.Parallel()

	_, err := VerifyExactDomainAuthority(context.Background(), staticTXTResolver{}, "missing.example.com")
	if err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestValidateRegistryOriginRejectsIPLiteral(t *testing.T) {
	t.Parallel()

	if _, err := validateRegistryOrigin("https://127.0.0.1:8443"); err == nil {
		t.Fatal("expected IP literal rejection")
	}
}

func TestStaticTXTResolverNotFound(t *testing.T) {
	t.Parallel()

	_, err := staticTXTResolver{}.LookupTXT(context.Background(), "_awid.example.com")
	var dnsErr *net.DNSError
	if err == nil || !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("expected not-found DNSError, got %v", err)
	}
}
