package awid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const FederationAuthorityStatementVersion = "aweb.federation-authority.dns.v1"

var federationDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type FederationAuthorityError struct {
	Reason string
}

func (e *FederationAuthorityError) Error() string { return e.Reason }

type FederationErrorSpec struct {
	HTTPStatus         int
	Retryable          bool
	RetryAfterRequired bool
}

var federationErrorSpecs = map[string]FederationErrorSpec{
	"contact_identity_binding_required":               {409, false, false},
	"federation_authority_cas_conflict":               {503, true, false},
	"federation_authority_coordination_unavailable":   {503, true, false},
	"federation_conversation_invalid":                 {409, false, false},
	"federation_envelope_invalid":                     {422, false, false},
	"federation_message_replay_conflict":              {409, false, false},
	"federation_rate_limited":                         {429, true, true},
	"federation_resolver_busy":                        {503, true, false},
	"federation_route_rejected":                       {502, false, false},
	"federation_route_timeout":                        {504, true, false},
	"federation_route_unavailable":                    {503, true, false},
	"federation_signature_invalid":                    {422, false, false},
	"federation_timestamp_invalid":                    {422, false, false},
	"local_recipient_route_missing":                   {404, false, false},
	"local_sender_route_mismatch":                     {422, false, false},
	"recipient_address_did_mismatch":                  {422, false, false},
	"recipient_current_key_mismatch":                  {422, false, false},
	"recipient_encryption_assertion_invalid_or_stale": {422, false, false},
	"recipient_encryption_assertion_missing":          {424, false, false},
	"recipient_identity_not_found":                    {404, false, false},
	"recipient_policy_rejected":                       {403, false, false},
	"recipient_route_mismatch":                        {422, false, false},
	"recipient_route_missing":                         {424, false, false},
	"sender_address_did_mismatch":                     {422, false, false},
	"sender_address_required":                         {422, false, false},
	"sender_address_wrapper_mismatch":                 {422, false, false},
	"sender_current_key_mismatch":                     {422, false, false},
	"sender_did_log_invalid":                          {422, false, false},
	"sender_did_log_rollback":                         {409, false, false},
	"sender_did_log_split_view":                       {409, false, false},
	"sender_identity_evidence_too_large":              {502, false, false},
	"sender_identity_not_found":                       {404, false, false},
	"sender_identity_unverifiable":                    {503, true, false},
	"sender_registry_discovery_failed":                {503, true, false},
	"sender_registry_origin_forbidden":                {422, false, false},
	"sender_registry_protocol_invalid":                {502, false, false},
	"sender_registry_tls_invalid":                     {502, false, false},
	"sender_registry_unavailable":                     {503, true, false},
	"sender_registry_unresolvable":                    {422, false, false},
	"sender_route_mismatch":                           {422, false, false},
	"sender_route_missing":                            {424, false, false},
	"target_route_mismatch":                           {421, false, false},
}

func FederationErrorSpecFor(reason string) (FederationErrorSpec, bool) {
	spec, ok := federationErrorSpecs[reason]
	return spec, ok
}

func federationReason(reason string) error { return &FederationAuthorityError{Reason: reason} }

func IsFederationReason(err error, reason string) bool {
	var target *FederationAuthorityError
	return errorsAs(err, &target) && target.Reason == reason
}

// errorsAs is a small indirection to keep the authority surface independent of
// callers' wrapping style.
func errorsAs(err error, target interface{}) bool {
	return errors.As(err, target)
}

func CanonicalFederationAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Count(raw, "/") != 1 || strings.Contains(raw, `\`) {
		return "", federationReason("sender_registry_unresolvable")
	}
	domain, name, _ := strings.Cut(raw, "/")
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || name == "" || len(domain) > 253 || !isASCII(domain) {
		return "", federationReason("sender_registry_unresolvable")
	}
	if _, err := netip.ParseAddr(strings.Trim(domain, "[]")); err == nil {
		return "", federationReason("sender_registry_unresolvable")
	}
	for _, label := range strings.Split(domain, ".") {
		if !federationDNSLabel.MatchString(label) {
			return "", federationReason("sender_registry_unresolvable")
		}
	}
	for _, r := range name {
		if unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return "", federationReason("sender_registry_unresolvable")
		}
	}
	return domain + "/" + name, nil
}

func canonicalFederationDomain(raw string) (string, error) {
	address, err := CanonicalFederationAddress(raw + "/_")
	if err != nil {
		return "", err
	}
	domain, _, _ := strings.Cut(address, "/")
	return domain, nil
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 0x7f {
			return false
		}
	}
	return true
}

type FederationOriginContext struct {
	AppEnv                string
	FederationTestEnabled bool
	ListenerOrigin        string
}

type FederationTXTLookup struct {
	Outcome string
	Records []string
}

type FederationTXTOutcomeResolver interface {
	LookupFederationTXT(ctx context.Context, name string) (FederationTXTLookup, error)
}

type NetFederationTXTResolver struct {
	Resolver *net.Resolver
}

func (r *NetFederationTXTResolver) LookupFederationTXT(ctx context.Context, name string) (FederationTXTLookup, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsNotFound:
				return FederationTXTLookup{Outcome: "nxdomain"}, nil
			case dnsErr.IsTimeout:
				return FederationTXTLookup{Outcome: "timeout"}, nil
			}
		}
		return FederationTXTLookup{Outcome: "servfail"}, nil
	}
	for _, record := range records {
		if strings.HasPrefix(strings.TrimSpace(record), "awid=") {
			return FederationTXTLookup{Outcome: "record", Records: records}, nil
		}
	}
	return FederationTXTLookup{Outcome: "no_awid_record", Records: records}, nil
}

type StrictFederationRegistryAuthority struct {
	Selection        string
	AuthorityName    string
	ControllerDID    string
	Inherited        bool
	RegistryExplicit bool
	RegistryOrigin   string
}

func DiscoverStrictFederationRegistry(ctx context.Context, resolver FederationTXTOutcomeResolver, senderDomain, registeredDomain string, originContext FederationOriginContext) (StrictFederationRegistryAuthority, error) {
	canonicalAddress, err := CanonicalFederationAddress(senderDomain + "/_")
	if err != nil {
		return StrictFederationRegistryAuthority{}, federationReason("sender_registry_discovery_failed")
	}
	canonicalDomain, _, _ := strings.Cut(canonicalAddress, "/")
	boundaryAddress, err := CanonicalFederationAddress(registeredDomain + "/_")
	if err != nil {
		return StrictFederationRegistryAuthority{}, federationReason("sender_registry_discovery_failed")
	}
	boundary, _, _ := strings.Cut(boundaryAddress, "/")
	if canonicalDomain != boundary && !strings.HasSuffix(canonicalDomain, "."+boundary) {
		return StrictFederationRegistryAuthority{}, federationReason("sender_registry_discovery_failed")
	}
	labels := strings.Split(canonicalDomain, ".")
	boundaryLabels := strings.Split(boundary, ".")
	for index := 0; index <= len(labels)-len(boundaryLabels); index++ {
		candidate := strings.Join(labels[index:], ".")
		name := "_awid." + candidate
		lookup, err := resolver.LookupFederationTXT(ctx, name)
		if err != nil {
			return StrictFederationRegistryAuthority{}, federationReason("sender_registry_discovery_failed")
		}
		switch lookup.Outcome {
		case "nxdomain", "nodata", "no_awid_record":
			continue
		case "record":
		default:
			return StrictFederationRegistryAuthority{}, federationReason("sender_registry_discovery_failed")
		}
		records := make([]string, 0, len(lookup.Records))
		for _, record := range lookup.Records {
			record = strings.TrimSpace(record)
			if strings.HasPrefix(record, "awid=") {
				records = append(records, record)
			}
		}
		if len(records) != 1 {
			return StrictFederationRegistryAuthority{}, federationReason("sender_registry_discovery_failed")
		}
		controller, registry, explicit, err := parseStrictFederationTXT(records[0], originContext)
		if err != nil {
			return StrictFederationRegistryAuthority{}, err
		}
		return StrictFederationRegistryAuthority{
			Selection:        "dns",
			AuthorityName:    name,
			ControllerDID:    controller,
			Inherited:        candidate != canonicalDomain,
			RegistryExplicit: explicit,
			RegistryOrigin:   registry,
		}, nil
	}
	return StrictFederationRegistryAuthority{
		Selection:        "public_default",
		AuthorityName:    "",
		Inherited:        false,
		RegistryExplicit: false,
		RegistryOrigin:   DefaultAWIDRegistryURL,
	}, nil
}

func parseStrictFederationTXT(record string, originContext FederationOriginContext) (string, string, bool, error) {
	fields := map[string]string{}
	for _, raw := range strings.Split(record, ";") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || value == "" || (key != "awid" && key != "controller" && key != "registry") {
			return "", "", false, federationReason("sender_registry_discovery_failed")
		}
		if _, exists := fields[key]; exists {
			return "", "", false, federationReason("sender_registry_discovery_failed")
		}
		fields[key] = value
	}
	if fields["awid"] != "v1" {
		return "", "", false, federationReason("sender_registry_discovery_failed")
	}
	controller := fields["controller"]
	if _, err := ExtractPublicKey(controller); err != nil {
		return "", "", false, federationReason("sender_registry_discovery_failed")
	}
	registry, explicit := fields["registry"]
	if !explicit {
		registry = DefaultAWIDRegistryURL
	}
	registry, err := CanonicalFederationRegistryOrigin(registry, originContext)
	if err != nil {
		return "", "", false, err
	}
	return controller, registry, explicit, nil
}

func CanonicalFederationRegistryOrigin(raw string, context FederationOriginContext) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", federationReason("sender_registry_origin_forbidden")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", federationReason("sender_registry_origin_forbidden")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if !isASCII(host) {
		return "", federationReason("sender_registry_origin_forbidden")
	}
	isolated := isolatedFederationHTTP(host, context)
	if parsed.Scheme != "https" && !isolated {
		return "", federationReason("sender_registry_origin_forbidden")
	}
	if _, err := netip.ParseAddr(host); err == nil && !isolated {
		return "", federationReason("sender_registry_origin_forbidden")
	}
	if parsed.Scheme == "http" && !isIsolatedFederationHost(host) {
		return "", federationReason("sender_registry_origin_forbidden")
	}
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	hostOut := host
	if strings.Contains(host, ":") {
		hostOut = "[" + host + "]"
	}
	if port != "" {
		hostOut += ":" + port
	}
	return parsed.Scheme + "://" + hostOut, nil
}

func isolatedFederationHTTP(host string, context FederationOriginContext) bool {
	if strings.ToLower(strings.TrimSpace(context.AppEnv)) != "development" || !context.FederationTestEnabled {
		return false
	}
	listener, err := url.Parse(context.ListenerOrigin)
	return err == nil && isIsolatedFederationHost(host) && isIsolatedFederationHost(listener.Hostname())
}

func isIsolatedFederationHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsLoopback()
	}
	return !strings.Contains(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".test.local")
}

var forbiddenFederationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func federationIPAllowed(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range forbiddenFederationPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func ValidateFederationResolvedIPs(values []string) ([]string, error) {
	return validateFederationResolvedIPs(values, false)
}

type FederationSourceIP struct {
	SourceIP            *string
	ForwardedHeaderUsed bool
	UnknownBucket       bool
}

func NormalizeFederationSourceIP(directPeer, forwardedFor string, trustedProxyCIDRs []string) FederationSourceIP {
	peer, err := netip.ParseAddr(strings.TrimSpace(directPeer))
	if err != nil {
		return FederationSourceIP{UnknownBucket: true}
	}
	networks := make([]netip.Prefix, 0, len(trustedProxyCIDRs))
	for _, value := range trustedProxyCIDRs {
		network, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return FederationSourceIP{UnknownBucket: true}
		}
		networks = append(networks, network)
	}
	trusted := func(address netip.Addr) bool {
		for _, network := range networks {
			if network.Contains(address) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		value := peer.String()
		return FederationSourceIP{SourceIP: &value}
	}
	hops := strings.Split(forwardedFor, ",")
	parsed := make([]netip.Addr, 0, len(hops))
	for _, value := range hops {
		hop, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return FederationSourceIP{UnknownBucket: true}
		}
		parsed = append(parsed, hop)
	}
	for index := len(parsed) - 1; index >= 0; index-- {
		if !trusted(parsed[index]) {
			value := parsed[index].String()
			return FederationSourceIP{SourceIP: &value, ForwardedHeaderUsed: true}
		}
	}
	return FederationSourceIP{ForwardedHeaderUsed: true, UnknownBucket: true}
}

func validateFederationResolvedIPs(values []string, allowNonPublicTest bool) ([]string, error) {
	approved := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		allowedTestAddress := err == nil && allowNonPublicTest && (addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast())
		if err != nil || (!federationIPAllowed(addr) && !allowedTestAddress) {
			return nil, federationReason("sender_registry_origin_forbidden")
		}
		canonical := addr.String()
		if _, ok := seen[canonical]; !ok {
			approved = append(approved, canonical)
			seen[canonical] = struct{}{}
		}
	}
	if len(approved) == 0 {
		return nil, federationReason("sender_registry_origin_forbidden")
	}
	return approved, nil
}

type FederationAuthorityStatement struct {
	CanonicalPayload []byte
	Version          string
	Digest           string
}

func NewFederationAuthorityStatement(payload map[string]interface{}) (*FederationAuthorityStatement, error) {
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return &FederationAuthorityStatement{
		CanonicalPayload: canonical,
		Version:          FederationAuthorityStatementVersion,
		Digest:           "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

type StrictFederationCheckpoint struct {
	Seq           int
	EntryHash     string
	StateHash     string
	CurrentDIDKey string
	Revision      int64
}

type StrictFederationVerifiedLog struct {
	Seq                int
	EntryHash          string
	StateHash          string
	CurrentDIDKey      string
	ContainsCheckpoint bool
}

func VerifyStrictFederationDIDLog(ctx context.Context, didAW string, entries []DidKeyEvidence, expectedCurrentDIDKey string, checkpoint *StrictFederationCheckpoint) (*StrictFederationVerifiedLog, error) {
	if err := ctx.Err(); err != nil {
		return nil, federationReason("sender_identity_unverifiable")
	}
	if len(entries) == 0 {
		return nil, federationReason("sender_identity_unverifiable")
	}
	if len(entries) > 4096 {
		return nil, federationReason("sender_identity_evidence_too_large")
	}
	if entries[0].Seq != 1 {
		return nil, federationReason("sender_did_log_invalid")
	}
	head, err := VerifyDidLogEntries(didAW, entries, time.Now())
	if err != nil || head == nil {
		return nil, federationReason("sender_did_log_invalid")
	}
	contains := checkpoint == nil
	if checkpoint != nil {
		if head.Seq < checkpoint.Seq {
			return nil, federationReason("sender_did_log_rollback")
		}
		for _, entry := range entries {
			if entry.Seq == checkpoint.Seq {
				if entry.EntryHash != checkpoint.EntryHash || entry.StateHash != checkpoint.StateHash || entry.NewDIDKey != checkpoint.CurrentDIDKey {
					return nil, federationReason("sender_did_log_split_view")
				}
				contains = true
				break
			}
		}
		if !contains {
			return nil, federationReason("sender_did_log_split_view")
		}
	}
	if strings.TrimSpace(expectedCurrentDIDKey) != "" && head.CurrentDIDKey != expectedCurrentDIDKey {
		return nil, federationReason("sender_current_key_mismatch")
	}
	return &StrictFederationVerifiedLog{
		Seq:                head.Seq,
		EntryHash:          head.EntryHash,
		StateHash:          head.StateHash,
		CurrentDIDKey:      head.CurrentDIDKey,
		ContainsCheckpoint: contains,
	}, nil
}
