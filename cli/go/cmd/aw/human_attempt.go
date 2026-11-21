package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/awebai/aw/awid"
)

// Restart never extends a signed deadline or destroys the old proof. Enrollment
// with a checked confirmation must finish activation, which has no such cutoff.
func restartHumanAttempt(path string, request map[string]any, now int64, restart, activation bool) (string, error) {
	if activation {
		if restart {
			return "", usageError("a confirmation is saved; resume activation without --restart")
		}
		return "", nil
	}
	deadline, ok := request["deadline"].(interface{ Int64() (int64, error) })
	if !ok {
		return "", usageError("saved attempt has no valid deadline")
	}
	d, err := deadline.Int64()
	if err != nil || d <= 0 {
		return "", usageError("saved attempt has no valid deadline")
	}
	if now < d {
		if restart {
			return "", usageError("saved attempt is not expired; resume it without --restart")
		}
		return "", nil
	}
	if !restart {
		return "", usageError("saved attempt expired; use --restart to preserve it and request a fresh attempt (a new person needs a fresh --intent FILE from the issuer)")
	}
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".expired-*")
	if err != nil {
		return "", err
	}
	archive := file.Name()
	if err = file.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(path, archive); err != nil {
		_ = os.Remove(archive)
		return "", err
	}
	return archive, nil
}

func enrollmentKeyCount(text string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || n < 1 || n > 8 {
		return 0, usageError("enter the number of keys you personally registered (1 to 8)")
	}
	return n, nil
}

func reviewEnrollmentKeys(material map[string]any, expected int, output io.Writer, confirm awid.ConfirmPrompt) error {
	registrations, _ := material["registrations"].([]any)
	if expected < 1 || expected > 8 || len(registrations) != expected {
		return usageError("registration_count_mismatch: you expected %d keys but the service returned %d; do not bind unexpected keys", expected, len(registrations))
	}
	fmt.Fprintln(output, "Approval keys returned by the service (credential IDs; the issuer checks their grades):")
	for n, value := range registrations {
		id := enrollmentText(enrollmentObject(enrollmentObject(value)["registration"])["id"])
		if id == "" {
			return usageError("registration has no credential ID")
		}
		fmt.Fprintf(output, "  %d. %q\n", n+1, id)
	}
	fmt.Fprint(output, enrollmentKeyAdvice(expected))
	yes, err := confirm("Do these keys match the keys you registered? Type yes to let your issuer bind them [y/N]: ")
	if err != nil {
		return err
	}
	if !yes {
		return usageError("binding not approved; enrollment saved, no keys bound")
	}
	return nil
}

func enrollmentKeyAdvice(count int) string {
	if count != 1 {
		return ""
	}
	return "Only one approval key is enrolled. Enroll a second key during the initial enrollment. Adding or replacing keys after activation is not implemented; losing your only key means the operator must issue a new ID and revoke the old ID.\n"
}

func enrolledKeyCount(binding map[string]any) int {
	credentials, _ := enrollmentObject(binding["binding"])["credentials"].([]any)
	return len(credentials)
}
