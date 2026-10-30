package awid

import (
	"context"
	"errors"
	"strings"
)

// verifyIDNamespaceAuthority binds the child's current controller to a found
// TXT anchor. Inherited TXT authenticates AWID's parent-authorized child
// record, never the child's controller directly (docs/id-certificates.md §2).
func verifyIDNamespaceAuthority(domain string, authority DomainAuthority, controller string, delegation map[string]any) error {
	bad := idCertificateRefusal("evidence_unavailable")
	if !idCertificateDomain(domain) || !idCertificateIDValid(controller, true) || !idCertificateIDValid(authority.ControllerDID, true) {
		return bad
	}
	if !authority.Inherited {
		if authority.DNSName != AWIDTXTName(domain) || authority.ControllerDID != controller {
			return bad
		}
		return nil
	}
	if !idStatusFields(delegation, "parent_domain parent_controller_key controller_key") {
		return bad
	}
	parent, ok := delegation["parent_domain"].(string)
	if !ok || !idCertificateDomain(parent) || !strings.HasSuffix(domain, "."+parent) || authority.DNSName != AWIDTXTName(parent) || delegation["parent_controller_key"] != authority.ControllerDID || delegation["controller_key"] != controller {
		return bad
	}
	return nil
}

// IDNamespaceController selects the controller for issuance preflights. An
// exact TXT needs no registry row for initial BYOT setup. An inherited TXT
// requires the delegate registry's witnessed child record before its key is used.
func (c *RegistryClient) IDNamespaceController(ctx context.Context, domain, registryURL string, authority DomainAuthority) (string, error) {
	controller := authority.ControllerDID
	var delegation map[string]any
	if authority.Inherited {
		namespace, _, err := c.GetNamespaceAt(ctx, registryURL, domain)
		if err != nil {
			var refused *RegistryError
			if errors.As(err, &refused) && refused.StatusCode == 404 {
				return "", idCertificateRefusal("evidence_unavailable")
			}
			return "", err
		}
		if namespace.Domain != domain {
			return "", idCertificateRefusal("evidence_unavailable")
		}
		controller, delegation = namespace.ControllerDID, namespace.Delegation
	}
	if err := verifyIDNamespaceAuthority(domain, authority, controller, delegation); err != nil {
		return "", err
	}
	return controller, nil
}
