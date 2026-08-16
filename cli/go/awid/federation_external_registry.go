package awid

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type StrictFederationHostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type StrictFederationHTTPFactory func(origin string, approvedIPs []string, generation int64) (*http.Client, error)

type StrictFederationExternalResolver struct {
	TXTResolver   FederationTXTOutcomeResolver
	HostResolver  StrictFederationHostResolver
	HTTPFactory   StrictFederationHTTPFactory
	OriginContext FederationOriginContext
	TLSConfig     *tls.Config
}

type StrictFederationExternalEvidence struct {
	CanonicalAddress          string
	AuthoritySelection        string
	AuthorityName             string
	ControllerDID             string
	AuthorityStatementVersion string
	AuthorityStatementDigest  string
	Inherited                 bool
	RegistryExplicit          bool
	RegistryOrigin            string
	AddressID                 *string
	DIDAW                     string
	CurrentDIDKey             string
	DeliveryOrigin            string
	AuthorityGeneration       int64
	ApprovedIPs               []string
	VerifiedLog               *StrictFederationVerifiedLog
}

func (e *StrictFederationExternalEvidence) CompareClaim(didAW, currentDIDKey, deliveryOrigin string) error {
	if e == nil || e.DIDAW != didAW {
		return federationReason("sender_address_did_mismatch")
	}
	if e.CurrentDIDKey != currentDIDKey {
		return federationReason("sender_current_key_mismatch")
	}
	if e.DeliveryOrigin != deliveryOrigin {
		return federationReason("sender_route_mismatch")
	}
	return nil
}

type strictNamespaceResponse struct {
	Domain        string `json:"domain"`
	ControllerDID string `json:"controller_did"`
}

type strictAddressResponse struct {
	AddressID     *string `json:"address_id"`
	Domain        string  `json:"domain"`
	Name          string  `json:"name"`
	DIDAW         string  `json:"did_aw"`
	CurrentDIDKey string  `json:"current_did_key"`
	Delivery      *struct {
		Origin string `json:"origin"`
	} `json:"delivery"`
}

type strictKeyResponse struct {
	DIDAW         string          `json:"did_aw"`
	CurrentDIDKey string          `json:"current_did_key"`
	LogHead       *DidKeyEvidence `json:"log_head"`
	Status        string          `json:"status"`
}

func (r *StrictFederationExternalResolver) FetchEvidence(ctx context.Context, address string, generation int64, checkpoint *StrictFederationCheckpoint) (*StrictFederationExternalEvidence, error) {
	canonical, err := CanonicalFederationAddress(address)
	if err != nil {
		return nil, err
	}
	if generation < 1 || r == nil {
		return nil, federationReason("sender_registry_unresolvable")
	}
	txtResolver := r.TXTResolver
	if txtResolver == nil {
		txtResolver = &NetFederationTXTResolver{}
	}
	domain, name, _ := strings.Cut(canonical, "/")
	deadline := time.Now().Add(5 * time.Second)
	if existing, ok := ctx.Deadline(); ok && existing.Before(deadline) {
		deadline = existing
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	authority, err := DiscoverStrictFederationRegistry(
		ctx,
		txtResolver,
		domain,
		registeredDomainBoundary(domain),
		r.OriginContext,
	)
	if err != nil {
		return nil, err
	}
	parsedOrigin, err := url.Parse(authority.RegistryOrigin)
	if err != nil || parsedOrigin.Hostname() == "" {
		return nil, federationReason("sender_registry_origin_forbidden")
	}
	hostResolver := r.HostResolver
	if hostResolver == nil {
		hostResolver = net.DefaultResolver
	}
	addresses, err := hostResolver.LookupNetIP(ctx, "ip", parsedOrigin.Hostname())
	if err != nil {
		return nil, federationReason("sender_registry_unavailable")
	}
	values := make([]string, 0, len(addresses))
	for _, value := range addresses {
		values = append(values, value.String())
	}
	approved, err := validateFederationResolvedIPs(
		values,
		isolatedFederationHTTP(parsedOrigin.Hostname(), r.OriginContext),
	)
	if err != nil {
		return nil, err
	}
	factory := r.HTTPFactory
	if factory == nil {
		factory = func(origin string, ips []string, generation int64) (*http.Client, error) {
			return NewPinnedFederationHTTPClient(origin, ips, generation, r.TLSConfig)
		}
	}
	client, err := factory(authority.RegistryOrigin, approved, generation)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()

	var namespace strictNamespaceResponse
	if err := strictFederationGetJSON(ctx, client, authority.RegistryOrigin, "/v1/namespaces/"+url.PathEscape(domain), &namespace); err != nil {
		return nil, err
	}
	namespaceDomain, domainErr := canonicalFederationDomain(namespace.Domain)
	if domainErr != nil || namespaceDomain != domain || namespace.ControllerDID == "" ||
		(authority.Selection == "dns" && namespace.ControllerDID != authority.ControllerDID) {
		return nil, federationReason("sender_address_did_mismatch")
	}
	if _, err := ExtractPublicKey(namespace.ControllerDID); err != nil {
		return nil, federationReason("sender_registry_protocol_invalid")
	}
	statement, err := NewFederationAuthorityStatement(map[string]interface{}{
		"authority_name":    authority.AuthorityName,
		"controller_did":    namespace.ControllerDID,
		"inherited":         authority.Inherited,
		"registry_explicit": authority.RegistryExplicit,
		"registry_origin":   authority.RegistryOrigin,
		"selection":         authority.Selection,
		"version":           "awid-v1",
	})
	if err != nil {
		return nil, federationReason("sender_registry_protocol_invalid")
	}

	var addressRow strictAddressResponse
	addressPath := "/v1/namespaces/" + url.PathEscape(domain) + "/addresses/" + url.PathEscape(name)
	if err := strictFederationGetJSON(ctx, client, authority.RegistryOrigin, addressPath, &addressRow); err != nil {
		return nil, err
	}
	addressDomain, domainErr := canonicalFederationDomain(addressRow.Domain)
	if domainErr != nil || addressDomain != domain || addressRow.Name != name || addressRow.DIDAW == "" || addressRow.CurrentDIDKey == "" {
		return nil, federationReason("sender_address_did_mismatch")
	}
	if addressRow.Delivery == nil || strings.TrimSpace(addressRow.Delivery.Origin) == "" {
		return nil, federationReason("sender_route_missing")
	}
	canonicalDelivery, err := canonicalServerOrigin(addressRow.Delivery.Origin)
	if err != nil || canonicalDelivery != addressRow.Delivery.Origin {
		return nil, federationReason("sender_registry_protocol_invalid")
	}

	var keyRow strictKeyResponse
	keyPath := "/v1/did/" + url.PathEscape(addressRow.DIDAW) + "/key"
	if err := strictFederationGetJSON(ctx, client, authority.RegistryOrigin, keyPath, &keyRow); err != nil {
		return nil, err
	}
	if keyRow.DIDAW != addressRow.DIDAW {
		return nil, federationReason("sender_address_did_mismatch")
	}
	if keyRow.CurrentDIDKey != addressRow.CurrentDIDKey {
		return nil, federationReason("sender_current_key_mismatch")
	}

	var verified *StrictFederationVerifiedLog
	if keyRow.Status != "OK_DEGRADED" && keyRow.LogHead != nil {
		if checkpoint != nil {
			switch {
			case keyRow.LogHead.Seq < checkpoint.Seq:
				return nil, federationReason("sender_did_log_rollback")
			case keyRow.LogHead.Seq == checkpoint.Seq && keyRow.LogHead.EntryHash != checkpoint.EntryHash:
				return nil, federationReason("sender_did_log_split_view")
			}
		}
		var cached *VerifiedLogHead
		if checkpoint != nil {
			cached = &VerifiedLogHead{
				Seq: checkpoint.Seq, EntryHash: checkpoint.EntryHash,
				StateHash: checkpoint.StateHash, CurrentDIDKey: checkpoint.CurrentDIDKey,
			}
		}
		outcome, head, verifyErr := VerifyDidKeyResolution(&DidKeyResolution{
			DIDAW: keyRow.DIDAW, CurrentDIDKey: keyRow.CurrentDIDKey, LogHead: keyRow.LogHead,
		}, cached, time.Now())
		if outcome == StableIdentityHardError {
			_ = verifyErr // diagnostics are deliberately not exposed across federation.
			return nil, federationReason("sender_did_log_invalid")
		}
		if outcome == StableIdentityVerified && head != nil {
			verified = &StrictFederationVerifiedLog{
				Seq: head.Seq, EntryHash: head.EntryHash, StateHash: head.StateHash,
				CurrentDIDKey: head.CurrentDIDKey, ContainsCheckpoint: checkpoint != nil || head.Seq == 1,
			}
		}
	}
	if verified == nil {
		var entries []DidKeyEvidence
		logPath := "/v1/did/" + url.PathEscape(addressRow.DIDAW) + "/log"
		if err := strictFederationGetJSON(ctx, client, authority.RegistryOrigin, logPath, &entries); err != nil {
			if IsFederationReason(err, "sender_identity_not_found") || IsFederationReason(err, "sender_registry_unavailable") {
				return nil, federationReason("sender_identity_unverifiable")
			}
			return nil, err
		}
		verified, err = VerifyStrictFederationDIDLog(ctx, addressRow.DIDAW, entries, addressRow.CurrentDIDKey, checkpoint)
		if err != nil {
			return nil, err
		}
	}

	return &StrictFederationExternalEvidence{
		CanonicalAddress:          canonical,
		AuthoritySelection:        authority.Selection,
		AuthorityName:             authority.AuthorityName,
		ControllerDID:             namespace.ControllerDID,
		AuthorityStatementVersion: statement.Version,
		AuthorityStatementDigest:  statement.Digest,
		Inherited:                 authority.Inherited,
		RegistryExplicit:          authority.RegistryExplicit,
		RegistryOrigin:            authority.RegistryOrigin,
		AddressID:                 addressRow.AddressID,
		DIDAW:                     addressRow.DIDAW,
		CurrentDIDKey:             addressRow.CurrentDIDKey,
		DeliveryOrigin:            addressRow.Delivery.Origin,
		AuthorityGeneration:       generation,
		ApprovedIPs:               approved,
		VerifiedLog:               verified,
	}, nil
}

func strictFederationGetJSON(ctx context.Context, client *http.Client, origin, path string, out interface{}) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+path, nil)
	if err != nil {
		return federationReason("sender_registry_protocol_invalid")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		if IsFederationReason(err, "sender_registry_tls_invalid") || IsFederationReason(err, "sender_registry_protocol_invalid") {
			return err
		}
		return federationReason("sender_registry_unavailable")
	}
	defer response.Body.Close()
	encoding := strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		return federationReason("sender_registry_protocol_invalid")
	}
	if response.StatusCode == http.StatusNotFound {
		return federationReason("sender_identity_not_found")
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return federationReason("sender_registry_unavailable")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return federationReason("sender_registry_protocol_invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 10*1024*1024+1))
	if err != nil {
		return federationReason("sender_registry_unavailable")
	}
	if len(body) > 10*1024*1024 {
		return federationReason("sender_identity_evidence_too_large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(out); err != nil {
		return federationReason("sender_registry_protocol_invalid")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return federationReason("sender_registry_protocol_invalid")
	}
	return nil
}
