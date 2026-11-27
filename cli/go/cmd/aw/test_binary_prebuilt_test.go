package main

import "testing"

func TestPrebuiltAwBinaryIsTakenFromTheCapturedEnvironment(t *testing.T) {
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{nil, ""},
		{[]string{"PATH=/bin"}, ""},
		{[]string{"AW_TEST_CLI_BINARY=/tmp/aw-cli/aw"}, "/tmp/aw-cli/aw"},
		{[]string{"AW_TEST_CLI_BINARY=/first", "AW_TEST_CLI_BINARY=/last"}, "/last"},
	} {
		if got := prebuiltAwBinary(tc.env); got != tc.want {
			t.Fatalf("prebuiltAwBinary(%q) = %q, want %q", tc.env, got, tc.want)
		}
	}
}
