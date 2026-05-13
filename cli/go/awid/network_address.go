package awid

import "strings"

const hostedHandleDomainSuffix = ".aweb.ai"

// NormalizeHostedHandleAddress converts @handle/agent shorthand into the
// canonical hosted address handle.aweb.ai/agent. Dotted handles are already
// explicit namespaces, so @acme.com/bot becomes acme.com/bot.
// This is the direct-recipient form; contact-handle namespace expansion is
// normalized server-side because bare @handle is not a direct recipient.
func NormalizeHostedHandleAddress(target string) string {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "@") {
		return target
	}
	ref := strings.TrimSpace(strings.TrimPrefix(target, "@"))
	domain, alias, ok := strings.Cut(ref, "/")
	if !ok {
		return target
	}
	domain = canonicalizeDomain(domain)
	alias = strings.TrimSpace(alias)
	if domain == "" || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") || alias == "" || strings.Contains(alias, "/") {
		return target
	}
	if !strings.Contains(domain, ".") {
		domain += hostedHandleDomainSuffix
	}
	return domain + "/" + alias
}

// NetworkAddress represents either a network address (domain/alias)
// or a plain local alias.
type NetworkAddress struct {
	Domain    string
	Alias     string
	IsNetwork bool
}

// ParseNetworkAddress parses a target string into a NetworkAddress.
// If the string contains a '/', it is treated as a network address (domain/alias).
// Otherwise it is a plain local alias.
func ParseNetworkAddress(target string) NetworkAddress {
	target = NormalizeHostedHandleAddress(target)
	if target == "" {
		return NetworkAddress{}
	}

	idx := strings.IndexByte(target, '/')
	if idx < 0 {
		return NetworkAddress{Alias: target}
	}

	domain := strings.TrimSpace(target[:idx])
	alias := strings.TrimSpace(target[idx+1:])
	if domain == "" || alias == "" || strings.ContainsRune(alias, '/') {
		return NetworkAddress{}
	}

	return NetworkAddress{
		Domain:    domain,
		Alias:     alias,
		IsNetwork: true,
	}
}

// String returns the canonical string form of the address.
func (a NetworkAddress) String() string {
	if a.IsNetwork {
		return a.Domain + "/" + a.Alias
	}
	return a.Alias
}
