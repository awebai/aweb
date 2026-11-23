package awid

// IDCertificateKind identifies the subject certified by an ID certificate.
type IDCertificateKind string

const (
	IDCertificateKindHuman IDCertificateKind = "human"
	IDCertificateKindAgent IDCertificateKind = "agent"
)

// IDParentKind identifies which authority signed an ID certificate.
type IDParentKind string

const (
	IDParentKindNamespace IDParentKind = "namespace"
	IDParentKindIdentity  IDParentKind = "identity"
)

// IDCertificateParent is a checked certificate's immediate parent, without a
// claim about that parent's present authority.
type IDCertificateParent struct {
	kind IDParentKind
	id   string
}

// Kind distinguishes a namespace controller from an identity parent.
func (parent IDCertificateParent) Kind() IDParentKind { return parent.kind }

// ID is the parent's namespace or identity ID, as selected by Kind.
func (parent IDCertificateParent) ID() string { return parent.id }

// IDCertificateView exposes a structurally checked, self-consistent certificate.
// Its signature alone does not establish current authority or human ancestry;
// VerifyIDChain must check the chain against current registry evidence.
type IDCertificateView struct {
	id        string
	domain    string
	kind      IDCertificateKind
	parent    IDCertificateParent
	issuerKey string
	issuedAt  string
	fields    map[string]any
	signed    map[string]any
}

// ID is the certified identity, independent of its current signing key.
func (certificate IDCertificateView) ID() string { return certificate.id }

// Domain is the certificate's governing identity namespace.
func (certificate IDCertificateView) Domain() string { return certificate.domain }

// Kind is the certificate's declared subject kind.
func (certificate IDCertificateView) Kind() IDCertificateKind { return certificate.kind }

// Parent is the immediate parent recorded in the signed certificate.
func (certificate IDCertificateView) Parent() IDCertificateParent { return certificate.parent }

// IssuerKey is the key that signed this certificate, not a current-key verdict.
func (certificate IDCertificateView) IssuerKey() string { return certificate.issuerKey }

// IssuedAt is the exact signed UTC timestamp, without reformatting.
func (certificate IDCertificateView) IssuedAt() string { return certificate.issuedAt }

// Signed returns an independent copy of the certificate and its signature for
// existing map-based consumers. Changing it does not change this view.
func (certificate IDCertificateView) Signed() map[string]any {
	return copyIDObject(certificate.signed)
}

// Fields returns an independent copy of the exact signed certificate fields.
func (certificate IDCertificateView) Fields() map[string]any {
	return copyIDObject(certificate.fields)
}

// CertificateID is the protocol commitment to the signed certificate fields.
func (certificate IDCertificateView) CertificateID() (string, error) {
	return IDCertificateID(certificate.fields)
}

// IDChain is an immutable view of a checked ID-chain bundle. It preserves the
// released map/header APIs while keeping unchecked JSON out of typed consumers.
type IDChain struct {
	bundle       map[string]any
	certificates []IDCertificateView
}

// IDChainFromBundle checks the existing size, shape and per-certificate signature
// rules from docs/id-certificates.md §2 and owns an independent snapshot. It does
// not establish current parent authority; use VerifyIDChain for that decision.
func IDChainFromBundle(bundle map[string]any) (IDChain, error) {
	canonical, err := idCertificateCanonical(bundle)
	if err != nil {
		return IDChain{}, err
	}
	if len(canonical) > IDChainMaxBytes {
		return IDChain{}, idCertificateRefusal("bundle_too_large")
	}
	if err := idCertificateBundleShape(bundle); err != nil {
		return IDChain{}, err
	}
	snapshot := copyIDObject(bundle)
	entries, ok := snapshot["certificates"].([]any)
	if !ok {
		return IDChain{}, idCertificateRefusal("invalid_shape")
	}
	chain := IDChain{bundle: snapshot, certificates: make([]IDCertificateView, 0, len(entries))}
	for _, entry := range entries {
		signed, ok := entry.(map[string]any)
		if !ok {
			return IDChain{}, idCertificateRefusal("invalid_shape")
		}
		certificate, err := checkedIDCertificateView(signed)
		if err != nil {
			return IDChain{}, err
		}
		chain.certificates = append(chain.certificates, certificate)
	}
	return chain, nil
}

// Leaf returns the checked subject certificate. A zero IDChain returns an empty
// view; only a successful IDChainFromBundle establishes a nonempty chain.
func (chain IDChain) Leaf() IDCertificateView {
	if len(chain.certificates) == 0 {
		return IDCertificateView{}
	}
	return chain.certificates[len(chain.certificates)-1]
}

// Certificates returns checked views in signed namespace-to-subject order.
func (chain IDChain) Certificates() []IDCertificateView {
	return append([]IDCertificateView(nil), chain.certificates...)
}

// SignedCertificates supplies independent envelopes for existing map-based
// request builders, in the same order as Certificates.
func (chain IDChain) SignedCertificates() []any {
	signed := make([]any, len(chain.certificates))
	for index, certificate := range chain.certificates {
		signed[index] = certificate.Signed()
	}
	return signed
}

// Bundle returns an independent snapshot for the released map-based APIs.
func (chain IDChain) Bundle() map[string]any { return copyIDObject(chain.bundle) }

// Header returns the canonical X-AWID-ID-Chain encoding without changing any
// certificate's signed fields or signature.
func (chain IDChain) Header() (string, error) { return EncodeIDChainHeader(chain.bundle) }

func checkedIDCertificateView(signed map[string]any) (IDCertificateView, error) {
	fields, err := idCertificateShape(signed)
	if err != nil {
		return IDCertificateView{}, err
	}
	id, idOK := fields["id"].(string)
	domain, domainOK := fields["domain"].(string)
	kind, kindOK := fields["kind"].(string)
	issuerKey, issuerOK := fields["issuer_key"].(string)
	issuedAt, issuedOK := fields["issued_at"].(string)
	parent, parentOK := fields["parent"].(map[string]any)
	if !idOK || !domainOK || !kindOK || !issuerOK || !issuedOK || !parentOK {
		return IDCertificateView{}, idCertificateRefusal("invalid_shape")
	}
	parentID, parentIDOK := parent["id"].(string)
	parentKind, parentKindOK := parent["kind"].(string)
	if !parentIDOK || !parentKindOK {
		return IDCertificateView{}, idCertificateRefusal("invalid_shape")
	}
	return IDCertificateView{
		id: id, domain: domain, kind: IDCertificateKind(kind), issuerKey: issuerKey, issuedAt: issuedAt,
		parent: IDCertificateParent{id: parentID, kind: IDParentKind(parentKind)}, fields: fields, signed: signed,
	}, nil
}

// copyIDObject copies the JSON containers in an already checked ID artifact.
// Its leaves are immutable JSON scalars; no caller gets the owned containers.
func copyIDObject(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	copy := make(map[string]any, len(source))
	for key, value := range source {
		copy[key] = copyIDValue(value)
	}
	return copy
}

func copyIDValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return copyIDObject(value)
	case []any:
		copy := make([]any, len(value))
		for index, item := range value {
			copy[index] = copyIDValue(item)
		}
		return copy
	default:
		return value
	}
}
