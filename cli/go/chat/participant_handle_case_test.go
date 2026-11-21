package chat

import "testing"

// A participant's name matches an address's handle without regard to case,
// as every other participant match does (chatIdentityMatches).
func TestUniqueHandleParticipantMatchIgnoresCase(t *testing.T) {
	for _, tc := range []struct {
		participant, target string
		want                bool
	}{
		{participant: "Bob", target: "myco/bob", want: true},
		{participant: "bob", target: "myco/BOB", want: true},
		{participant: "bobby", target: "myco/bob", want: false},
	} {
		if got := uniqueHandleParticipantMatch([]string{tc.participant}, nil, nil, tc.target); got != tc.want {
			t.Errorf("participant %q target %q: match=%v, want %v", tc.participant, tc.target, got, tc.want)
		}
	}
}
