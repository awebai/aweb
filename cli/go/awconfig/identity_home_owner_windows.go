//go:build windows

package awconfig

import "os"

func checkIdentityHomeOwner(_ string, _ os.FileInfo) error {
	// Windows profile ACLs govern access; ResolveIdentityHome checks readability.
	return nil
}
