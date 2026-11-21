package main

import "strings"

// firstNonEmpty preserves exact field contents while choosing the first value
// present. Signed fields and output DTOs may depend on those original bytes.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// firstNonEmptyString trims command/setting values and skips whitespace-only
// inputs. It intentionally differs from exact field selection above.
func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
