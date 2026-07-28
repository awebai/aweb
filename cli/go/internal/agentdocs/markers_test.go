package agentdocs

import (
	"strings"
	"testing"
)

func TestHasSingleMarkedBlockRequiresExactlyOneCompletePair(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{name: "single complete pair", content: Render("current"), want: true},
		{name: "unmarked", content: "profile body\n"},
		{name: "missing end", content: MarkerStart + "\ncurrent\n"},
		{name: "end before start", content: MarkerEnd + "\n" + MarkerStart + "\n"},
		{name: "duplicate pair", content: Render("old") + Render("current")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasSingleMarkedBlock(tc.content); got != tc.want {
				t.Fatalf("HasSingleMarkedBlock()=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestRemoveAllRemovesDuplicateCompleteBlocks(t *testing.T) {
	content := "# Profile\n\n" + Render("old") + "\nLocal note\n\n" + Render("stale")
	got := RemoveAll(content)
	if strings.Contains(got, MarkerStart) || strings.Contains(got, MarkerEnd) {
		t.Fatalf("RemoveAll retained markers:\n%s", got)
	}
	for _, want := range []string{"# Profile", "Local note"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RemoveAll discarded static content %q:\n%s", want, got)
		}
	}
}
