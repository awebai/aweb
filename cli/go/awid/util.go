package awid

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"strconv"
)

func urlQueryEscape(v string) string {
	return url.QueryEscape(v)
}

func urlPathEscape(v string) string {
	return url.PathEscape(v)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

// GenerateUUID4 returns a random UUID v4 string.
func GenerateUUID4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

