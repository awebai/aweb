//go:build windows

package awconfig

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func checkIdentityHomeOwner(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read identity home owner %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read identity home owner %s: %w", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current identity home user: %w", err)
	}
	if !owner.Equals(user.User.Sid) {
		return fmt.Errorf("identity home %s is not owned by the current user", path)
	}
	return nil
}
