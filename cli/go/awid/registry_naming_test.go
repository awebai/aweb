package awid

import "context"

// registryNaming is a registry in which every address belongs to one key and,
// when set, one stable identity.
type registryNaming struct {
	did      string
	stableID string
}

func (r registryNaming) Resolve(_ context.Context, address string) (*ResolvedIdentity, error) {
	return &ResolvedIdentity{
		DID: r.did, StableID: r.stableID, Address: address,
		Custody: CustodySelf, IdentityScope: IdentityModeGlobal, ResolvedVia: "registry",
	}, nil
}

// registryByAddress is a registry that names a key for each address it holds
// and answers that any other address does not exist.
type registryByAddress map[string]string

func (r registryByAddress) Resolve(_ context.Context, address string) (*ResolvedIdentity, error) {
	did, ok := r[address]
	if !ok {
		return nil, &RegistryError{StatusCode: 404, Detail: "address not found"}
	}
	return &ResolvedIdentity{
		DID: did, Address: address,
		Custody: CustodySelf, IdentityScope: IdentityModeGlobal, ResolvedVia: "registry",
	}, nil
}
