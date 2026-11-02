package main

import "testing"

// A reply without --subject answers the original subject once.
func TestReplySubject(t *testing.T) {
	for _, tc := range []struct{ explicit, original, want string }{
		{"", "hello", "Re: hello"},
		{"", "  hello  ", "Re: hello"},
		{"", "Re: hello", "Re: hello"},
		{"", "RE: hello", "RE: hello"},
		{"", "re:hello", "re:hello"},
		{"", "", "Re"},
		{"  ", "   ", "Re"},
		{"Plan B", "hello", "Plan B"},
		{"", "Regarding the plan", "Re: Regarding the plan"},
	} {
		if got := replySubject(tc.explicit, tc.original); got != tc.want {
			t.Errorf("replySubject(%q, %q) = %q, want %q", tc.explicit, tc.original, got, tc.want)
		}
	}
}
