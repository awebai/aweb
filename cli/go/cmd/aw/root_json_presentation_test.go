package main

import "testing"

func TestRawJSONFlagRespectsExplicitBooleanAndSeparator(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "plain", args: []string{"audit", "verify"}},
		{name: "trailing malformed command flag", args: []string{"audit", "verify", "--bad-flag", "--json"}, want: true},
		{name: "explicit true", args: []string{"audit", "verify", "--json=true"}, want: true},
		{name: "explicit false", args: []string{"audit", "verify", "--json=false"}},
		{name: "last flag wins", args: []string{"--json", "audit", "verify", "--json=false"}},
		{name: "separator hides flag", args: []string{"audit", "verify", "--", "--json"}},
		{name: "separator keeps preceding flag", args: []string{"--json", "audit", "verify", "--", "--json=false"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := argsContainJSONFlag(test.args); got != test.want {
				t.Fatalf("JSON selection=%t, want %t", got, test.want)
			}
		})
	}
}
