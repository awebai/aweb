package awid

// IdentityScope is the declared local/global lifetime and addressability model.
// Released string-based configuration fields and IdentityMode constants remain adapters.
type IdentityScope string

const (
	IdentityScopeLocal  IdentityScope = IdentityModeLocal
	IdentityScopeGlobal IdentityScope = IdentityModeGlobal
)

// IdentityCustody identifies who can use an identity private key; it does not grant team authority.
type IdentityCustody string

const (
	IdentityCustodySelf   IdentityCustody = CustodySelf
	IdentityCustodyHosted IdentityCustody = CustodyCustodial
)
