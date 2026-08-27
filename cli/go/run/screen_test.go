package run

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestAppendScreenTextTracksCompleteAndPartialLines(t *testing.T) {
	lines := []screenOutputLine{}
	current := screenOutputLine{}

	appendScreenText(&lines, &current, DisplayKindAgentText, "first line\nsecond")
	appendScreenText(&lines, &current, DisplayKindAgentText, " line\nthird line\n")

	if len(lines) != 3 {
		t.Fatalf("expected 3 completed lines, got %d", len(lines))
	}
	if lines[0].text != "first line" || lines[1].text != "second line" || lines[2].text != "third line" {
		t.Fatalf("unexpected completed lines: %#v", lines)
	}
	if current.text != "" {
		t.Fatalf("expected no trailing partial line, got %#v", current)
	}
}

func TestAppendScreenTextClearsEmptyTailKindAfterSeparator(t *testing.T) {
	lines := []screenOutputLine{}
	current := screenOutputLine{}

	appendScreenText(&lines, &current, DisplayKindPlain, "\n")
	if current != (screenOutputLine{}) {
		t.Fatalf("expected separator newline to leave no active current line, got %#v", current)
	}

	appendScreenText(&lines, &current, DisplayKindAgentText, "● **")
	appendScreenText(&lines, &current, DisplayKindAgentText, "P0:**")

	if current.kind != DisplayKindAgentText {
		t.Fatalf("expected assistant chunks after separator to keep agent kind, got %#v", current)
	}
	if current.text != "● **P0:**" {
		t.Fatalf("expected assistant line to preserve its prefix across chunks, got %#v", current)
	}
}

func TestStyleWrappedScreenLineUsesDisplayKinds(t *testing.T) {
	cases := []struct {
		kind DisplayKind
		line string
		want string
	}{
		{kind: DisplayKindPrompt, line: "> fix the bug", want: "prompt"},
		{kind: DisplayKindUserInput, line: "> fix the bug", want: "user"},
		{kind: DisplayKindTool, line: `· go test ./... 2>&1`, want: "tool"},
		{kind: DisplayKindToolDetail, line: `  file_path="/tmp/image.png"`, want: "tool_detail"},
		{kind: DisplayKindPlain, line: `   1. PTY default-off`, want: "plain"},
		{kind: DisplayKindCommunication, line: "● from dave (mail): please review this", want: "comms"},
		{kind: DisplayKindCommunication, line: "● to henry (chat)", want: "comms"},
		{kind: DisplayKindTaskActivity, line: "● task update aweb-aaat.1", want: "task"},
		{kind: DisplayKindProviderStderr, line: "provider stderr: approval required", want: "provider_stderr"},
		{kind: DisplayKindProviderStdout, line: "provider stdout: Allow? [y/N]", want: "provider_stdout"},
		{kind: DisplayKindDone, line: "done  2.1s", want: "done"},
		{kind: DisplayKindInfo, line: "info: session", want: "info"},
		{kind: DisplayKindHint, line: "type /wait, /autofeed off, /stop", want: "hint"},
		{kind: DisplayKindSeparator, line: "────────────────────────────────────────", want: "separator"},
		{kind: DisplayKindPlain, line: "plain text", want: "plain"},
	}

	for _, tc := range cases {
		got := "plain"
		switch tc.kind {
		case DisplayKindPrompt:
			got = "prompt"
		case DisplayKindUserInput:
			got = "user"
		case DisplayKindTool:
			got = "tool"
		case DisplayKindToolDetail:
			got = "tool_detail"
		case DisplayKindCommunication:
			got = "comms"
		case DisplayKindTaskActivity:
			got = "task"
		case DisplayKindProviderStderr:
			got = "provider_stderr"
		case DisplayKindProviderStdout:
			got = "provider_stdout"
		case DisplayKindDone:
			got = "done"
		case DisplayKindInfo:
			got = "info"
		case DisplayKindHint:
			got = "hint"
		case DisplayKindSeparator:
			got = "separator"
		}
		if got != tc.want {
			t.Fatalf("line %q: expected %s, got %s", tc.line, tc.want, got)
		}
	}
}

func TestStyleScreenLineStylesUserInputLabel(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindUserInput, text: `> review the retry path`}, styles)
	want := styles.userLabel.Render(`>`) + styles.userText.Render(` review the retry path`)
	if got != want {
		t.Fatalf("unexpected styled user line %q", got)
	}
}

func TestStyleScreenLineKeepsToolArgumentsNeutralOnFirstLine(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindTool, text: `· View /tmp/image.png`}, styles)
	want := styles.toolMuted.Render(`· View /tmp/image.png`)
	if got != want {
		t.Fatalf("unexpected styled tool line %q", got)
	}
}

func TestStyleScreenLineStylesAgentBulletLane(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindAgentText, text: `● first answer line`}, styles)
	want := styles.agentText.Render(`● first answer line`)
	if got != want {
		t.Fatalf("unexpected styled agent line %q", got)
	}
}

func TestStyleScreenLineDeemphasizesToolArgsAfterOpeningParen(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindTool, text: `· browser_click(ref="abc", element="Submit")`}, styles)
	want := styles.toolMuted.Render(`· browser_click(ref="abc", element="Submit")`)
	if got != want {
		t.Fatalf("unexpected styled tool line %q", got)
	}
}

func TestStyleScreenLineColorsClosingParenOnContinuation(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindToolDetail, text: `       offset=48)`}, styles)
	want := styles.toolMuted.Render(`       offset=48)`)
	if got != want {
		t.Fatalf("unexpected styled continuation line %q", got)
	}
}

func TestStyleScreenLineStylesCommLabel(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindCommunication, text: `● from dave (mail): merged to main`}, styles)
	want := styles.commsBullet.Render(`●`) + styles.comms.Render(` from dave (mail)`) + `: merged to main`
	if got != want {
		t.Fatalf("unexpected styled comm line %q", got)
	}
}

func TestStyleScreenLineStylesTaskLabel(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindTaskActivity, text: `● task update aweb-aaat.1`}, styles)
	want := styles.taskBullet.Render(`●`) + styles.task.Render(` task update aweb-aaat.1`)
	if got != want {
		t.Fatalf("unexpected styled task line %q", got)
	}
}

func TestStyleScreenLineStylesProviderStderrLabel(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(screenOutputLine{kind: DisplayKindProviderStderr, text: `provider stderr: approval required`}, styles)
	want := styles.streamLabel.Render(`provider stderr:`) + styles.streamError.Render(` approval required`)
	if got != want {
		t.Fatalf("unexpected provider stderr line %q", got)
	}
}

func TestScreenControllerSetInputLineKeepsLeadingSpace(t *testing.T) {
	screen := &ScreenController{promptLabel: "aw:repo:rose> "}

	screen.SetInputLine("aw:repo:rose>  leading")

	if !screen.pending {
		t.Fatal("expected leading-space input to count as pending")
	}
	if screen.inputLine != "aw:repo:rose>  leading" {
		t.Fatalf("expected input line to preserve leading space, got %q", screen.inputLine)
	}
}

func TestIdentityPromptLabelReturnsShortPrompt(t *testing.T) {
	got := IdentityPromptLabel("aweb", "github.com/awebai/aw", "", "rose")
	if got != ">> " {
		t.Fatalf("expected short prompt label, got %q", got)
	}
}

func TestComposeStatusLineShowsIdentityAlone(t *testing.T) {
	got := ComposeStatusLine("claude@aweb:aw:rose", "")
	if got != "claude@aweb:aw:rose" {
		t.Fatalf("expected identity alone, got %q", got)
	}
}

func TestComposeStatusLineAppendsTransientState(t *testing.T) {
	got := ComposeStatusLine("claude@aweb:aw:rose", "next run in 12s")
	if got != "claude@aweb:aw:rose · next run in 12s" {
		t.Fatalf("expected composed status, got %q", got)
	}
}

func TestComposeStatusLineShowsTransientAloneWhenNoIdentity(t *testing.T) {
	got := ComposeStatusLine("", "paused")
	if got != "paused" {
		t.Fatalf("expected transient alone, got %q", got)
	}
}

func TestStatusIdentityFormatsProviderAndIdentity(t *testing.T) {
	cases := []struct {
		provider string
		project  string
		repo     string
		alias    string
		want     string
	}{
		{"claude", "aweb", "aw", "rose", "claude@aweb:aw:rose"},
		{"codex", "aweb", "", "rose", "codex@aweb:rose"},
		{"claude", "", "", "rose", "claude@rose"},
		{"claude", "aweb", "aw", "", "claude@aweb:aw"},
		{"", "aweb", "aw", "rose", "aweb:aw:rose"},
		{"", "", "", "", ""},
	}
	for _, tc := range cases {
		got := StatusIdentity(tc.provider, tc.project, tc.repo, tc.alias)
		if got != tc.want {
			t.Fatalf("StatusIdentity(%q,%q,%q,%q) = %q, want %q", tc.provider, tc.project, tc.repo, tc.alias, got, tc.want)
		}
	}
}

func TestShortRepoNameFallsBackToRepoOrigin(t *testing.T) {
	got := ShortRepoName("", "git@github.com:awebai/aw.git")
	if got != "aw" {
		t.Fatalf("expected repo short name from repo origin, got %q", got)
	}
}

func TestWrapScreenLineWrapsLongToolFields(t *testing.T) {
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindToolDetail, text: `  command="git fetch origin main && git log --oneline origin/main -5"`}, 32)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if line == "" || line[:2] != "  " {
			t.Fatalf("expected wrapped continuation lines to keep indentation, got %#v", lines)
		}
	}
}

func TestWrapScreenLineKeepsToolArgIndent(t *testing.T) {
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindToolDetail, text: `       file_path="/Users/juanre/prj/beadhub-all/aw/run/screen.go",`}, 40)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if line == "" || line[:7] != "       " {
			t.Fatalf("expected wrapped continuation lines to keep tool arg indentation, got %#v", lines)
		}
	}
}

func TestWrapScreenLineUsesHangingIndentForCommLines(t *testing.T) {
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindCommunication, text: `● from dave (mail): this is a long coordination update that should wrap cleanly`}, 28)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	indent := strings.Repeat(" ", lipgloss.Width("● from dave (mail): "))
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, indent) {
			t.Fatalf("expected hanging indent under message body, got %#v", lines)
		}
	}
}

func TestWrapScreenLineUsesHangingIndentForAgentText(t *testing.T) {
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindAgentText, text: `● this is a long assistant reply that should wrap under the bullet lane cleanly`}, 28)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "  ") {
			t.Fatalf("expected assistant continuation indent, got %#v", lines)
		}
	}
}

func TestContentWidthForTerminalWidthUsesFullTerminalWidth(t *testing.T) {
	if got := contentWidthForTerminalWidth(120); got != 120 {
		t.Fatalf("expected wide terminal to use full width, got %d", got)
	}
	if got := contentWidthForTerminalWidth(50); got != 50 {
		t.Fatalf("expected terminal width 50 to use full width, got %d", got)
	}
}

func TestWrapScreenLineUsesHangingIndentForProviderStderr(t *testing.T) {
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindProviderStderr, text: `provider stderr: approval required because sandbox escalation was denied`}, 34)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, strings.Repeat(" ", len("provider stderr: "))) {
			t.Fatalf("expected stderr continuation to align under message body, got %#v", lines)
		}
	}
}

func TestWrapScreenLineKeepsIndentedCommBodyLinesAligned(t *testing.T) {
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindCommunication, text: `   ownership split we discussed: docs/id-sot.md is now a hosted pointer to canonical docs`}, 40)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "   ") {
			t.Fatalf("expected wrapped comm body to keep body indent, got %#v", lines)
		}
		if strings.HasPrefix(line, "                              ") {
			t.Fatalf("expected wrapped comm body to avoid label-style over-indent, got %#v", lines)
		}
	}
}

func TestWrapScreenLineTruncatesTopLevelToolLines(t *testing.T) {
	source := `· aw mail inbox --unread-only --format json 2>/dev/null | python3 -c "print(1)"`
	lines := wrapScreenLine(screenOutputLine{kind: DisplayKindTool, text: source}, 34)
	if len(lines) != 1 {
		t.Fatalf("expected single-line tool output, got %#v", lines)
	}
	if !strings.HasSuffix(lines[0], "…") {
		t.Fatalf("expected truncated tool line with ellipsis, got %#v", lines)
	}
	if lipgloss.Width(lines[0]) > 34 {
		t.Fatalf("expected truncated tool line to fit width, got %#v", lines)
	}
}

func TestAppendWrappedStyledScreenLineKeepsTopLevelToolLinesSingleLine(t *testing.T) {
	styles := newScreenStyles()
	source := screenOutputLine{kind: DisplayKindTool, text: `· aw mail inbox --unread-only --format json 2>/dev/null | python3 -c "print(1)"`}
	lines := appendWrappedStyledScreenLine(nil, source, 34, styles)
	if len(lines) != 1 {
		t.Fatalf("expected single styled tool line, got %#v", lines)
	}
	if !strings.Contains(lines[0], styles.toolMuted.Render(`…`)) {
		t.Fatalf("expected truncated tool line to stay muted, got %#v", lines)
	}
}

func TestScreenControllerFooterPlacesPromptAboveStatusWithoutDivider(t *testing.T) {
	screen := &ScreenController{
		promptLabel: ">> ",
		statusLine:  "paused",
		inputLine:   ">> hello",
		inputCursor: len([]rune("hello")),
		styles:      newScreenStyles(),
	}

	lines := screen.renderFooterLinesLocked(40)
	promptIdx := -1
	statusIdx := -1
	for i, line := range lines {
		switch {
		case strings.Contains(line, "hello"):
			promptIdx = i
		case strings.Contains(line, "paused"):
			statusIdx = i
		}
	}

	if promptIdx < 0 || statusIdx < 0 {
		t.Fatalf("expected prompt and status in footer, got %#v", lines)
	}
	if promptIdx >= statusIdx {
		t.Fatalf("expected prompt before status, got %#v", lines)
	}
	if statusIdx-promptIdx < 2 {
		t.Fatalf("expected blank line between prompt and status, got %#v", lines)
	}
	if lines[statusIdx-1] != "" {
		t.Fatalf("expected blank line before status, got %#v", lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "────") {
			t.Fatalf("expected footer divider to be absent, got %#v", lines)
		}
	}
}

func TestScreenControllerFooterSeparatesCurrentTextFromPrompt(t *testing.T) {
	screen := &ScreenController{
		promptLabel: ">> ",
		current:     screenOutputLine{kind: DisplayKindAgentText, text: "assistant reply"},
		inputLine:   ">> next",
		inputCursor: len([]rune("next")),
		styles:      newScreenStyles(),
	}

	lines := screen.renderFooterLinesLocked(40)
	replyIdx := -1
	promptIdx := -1
	for i, line := range lines {
		switch {
		case strings.Contains(line, "assistant reply"):
			replyIdx = i
		case strings.Contains(line, "next"):
			promptIdx = i
		}
	}

	if replyIdx < 0 || promptIdx < 0 {
		t.Fatalf("expected current text and prompt in footer, got %#v", lines)
	}
	if promptIdx-replyIdx < 2 {
		t.Fatalf("expected blank line between current text and prompt, got %#v", lines)
	}
	if lines[replyIdx+1] != "" {
		t.Fatalf("expected blank line after current text, got %#v", lines)
	}
}

func TestScreenControllerFooterSeparatesTranscriptHistoryFromPrompt(t *testing.T) {
	screen := &ScreenController{
		promptLabel: ">> ",
		lines:       []screenOutputLine{{kind: DisplayKindAgentText, text: "assistant reply"}},
		inputLine:   ">> next",
		inputCursor: len([]rune("next")),
		styles:      newScreenStyles(),
	}

	lines := screen.renderFooterLinesLocked(40)
	if len(lines) < 1 || lines[0] != "" {
		t.Fatalf("expected leading blank line before prompt when transcript exists, got %#v", lines)
	}
	if !strings.Contains(lines[1], "next") {
		t.Fatalf("expected prompt after leading blank line, got %#v", lines)
	}
}

func TestScreenControllerFooterCursorTracksPromptAfterHistorySpacer(t *testing.T) {
	screen := &ScreenController{
		promptLabel: ">> ",
		lines:       []screenOutputLine{{kind: DisplayKindAgentText, text: "assistant reply"}},
		inputLine:   ">> asdf",
		inputCursor: len([]rune("asdf")),
		styles:      newScreenStyles(),
	}

	layout := screen.renderFooterLayoutLocked(40)
	if layout.cursorLine != 1 {
		t.Fatalf("expected cursor on prompt line after history spacer, got line %d with %#v", layout.cursorLine, layout.lines)
	}
}

func TestScreenControllerRenderStatusLineShowsBusySpinner(t *testing.T) {
	screen := &ScreenController{
		statusLine:   "working",
		busy:         true,
		spinnerFrame: 2,
		styles:       newScreenStyles(),
	}

	line := screen.renderStatusLineLocked(40)
	if !strings.Contains(line, screenSpinnerFrames[2]) {
		t.Fatalf("expected spinner frame in status line, got %q", line)
	}
	if !strings.Contains(line, "WORKING") {
		t.Fatalf("expected explicit working label, got %q", line)
	}
	if !strings.Contains(line, "· working") {
		t.Fatalf("expected status text to remain after working label, got %q", line)
	}
}

func TestScreenControllerHistoryNavigation(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte("first"))
	screen.handleInlineInput([]byte{'\r'})
	screen.handleInlineInput([]byte("second"))
	screen.handleInlineInput([]byte{'\r'})
	screen.handleInlineInput([]byte{0x1b, '[', 'A'})

	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "second" {
		t.Fatalf("expected first history recall to show latest entry, got %q", got)
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'A'})
	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "first" {
		t.Fatalf("expected second history recall to show older entry, got %q", got)
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'B'})
	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "second" {
		t.Fatalf("expected down arrow to move forward in history, got %q", got)
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'B'})
	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "" {
		t.Fatalf("expected second down arrow to restore draft input, got %q", got)
	}
}

func TestScreenControllerBracketedPasteInsertsNewlines(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// Simulate bracketed paste: ESC[200~ hello\nworld\nparagraph ESC[201~
	paste := []byte("\x1b[200~hello\nworld\nparagraph\x1b[201~")
	screen.handleInlineInput(paste)

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld\nparagraph" {
		t.Fatalf("expected multi-line paste in buffer, got %q", value)
	}
	if screen.pasting {
		t.Fatal("expected pasting=false after paste end bracket")
	}

	// Should not have submitted anything yet — still in the input buffer
	var prompts []string
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				prompts = append(prompts, evt.Text)
			}
		default:
			goto done
		}
	}
done:
	if len(prompts) != 0 {
		t.Fatalf("expected no prompt submissions during paste, got %v", prompts)
	}

	// Now press Enter to submit the full multi-line text
	screen.handleInlineInput([]byte{'\r'})
	var submitted string
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				submitted = evt.Text
				goto submitted
			}
		default:
			t.Fatal("expected prompt event after Enter")
		}
	}
submitted:
	if submitted != "hello\nworld\nparagraph" {
		t.Fatalf("expected full multi-line text in submission, got %q", submitted)
	}
}

func TestScreenControllerBracketedPastePreservesCRNewlines(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// Terminals that send \r for newlines in pasted text (e.g. macOS Terminal)
	paste := []byte("\x1b[200~hello\rworld\rparagraph\x1b[201~")
	screen.handleInlineInput(paste)

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld\nparagraph" {
		t.Fatalf("expected \\r in paste to become newlines, got %q", value)
	}
}

func TestScreenControllerBracketedPastePreservesCRLFNewlines(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// Terminals that send \r\n for newlines in pasted text
	paste := []byte("\x1b[200~hello\r\nworld\r\nparagraph\x1b[201~")
	screen.handleInlineInput(paste)

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld\nparagraph" {
		t.Fatalf("expected \\r\\n in paste to become single newlines, got %q", value)
	}
}

func TestScreenControllerUnbracketedBulkPastePreservesNewlines(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// Terminals without bracketed paste support: a large chunk of text
	// arrives in a single read() call with \r characters. The handler
	// should detect this as a paste (many bytes at once) and preserve
	// newlines instead of submitting at each \r.
	bulk := []byte("first paragraph content here\rsecond paragraph with more text\rthird paragraph ending")
	screen.handleInlineInput(bulk)

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "first paragraph content here\nsecond paragraph with more text\nthird paragraph ending" {
		t.Fatalf("expected bulk paste to preserve newlines, got %q", value)
	}

	// Should not have submitted
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				t.Fatalf("expected no submission during bulk paste, got %q", evt.Text)
			}
		default:
			return
		}
	}
}

func TestScreenControllerSplitBracketEndSequence(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// Paste start arrives in one read, but the end bracket is split:
	// ESC arrives at end of first read, [201~ at start of second.
	screen.handleInlineInput([]byte("\x1b[200~hello world\x1b"))
	screen.handleInlineInput([]byte("[201~"))

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello world" {
		t.Fatalf("expected paste content preserved across split bracket, got %q", value)
	}
	if screen.pasting {
		t.Fatal("expected pasting=false after split end bracket")
	}
}

func TestScreenControllerSplitBracketStartSequence(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// The paste start bracket is split: ESC[20 at end of first read,
	// 0~ at start of second, then content and end bracket.
	screen.handleInlineInput([]byte("\x1b[20"))
	screen.handleInlineInput([]byte("0~hello\x1b[201~"))

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello" {
		t.Fatalf("expected paste content after split start bracket, got %q", value)
	}
	if screen.pasting {
		t.Fatal("expected pasting=false after end bracket")
	}
}

func TestScreenControllerBracketedPasteCRLFSplitAcrossReads(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// First read: bracketed paste start + text ending with \r
	screen.handleInlineInput([]byte("\x1b[200~hello\r"))
	// Second read: \n (second half of \r\n) + more text + paste end
	screen.handleInlineInput([]byte("\nworld\x1b[201~"))

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld" {
		t.Fatalf("expected split \\r\\n to produce single newline, got %q", value)
	}
}

func TestScreenControllerNewlineStillSubmitsOutsidePaste(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte("hello\r"))

	var submitted string
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				submitted = evt.Text
				goto done
			}
		default:
			t.Fatal("expected prompt event after Enter")
		}
	}
done:
	if submitted != "hello" {
		t.Fatalf("expected single-line submission, got %q", submitted)
	}
}

func TestScreenControllerCtrlJInsertsNewlineWithoutSubmitting(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte("hello\nworld"))

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld" {
		t.Fatalf("expected ctrl-j to insert newline, got %q", value)
	}
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				t.Fatalf("expected no submission on ctrl-j, got %q", evt.Text)
			}
		default:
			return
		}
	}
}

func TestScreenControllerShiftEnterSequenceInsertsNewlineWithoutSubmitting(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte("hello\x1b[13;2uworld"))

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld" {
		t.Fatalf("expected shift-enter sequence to insert newline, got %q", value)
	}
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				t.Fatalf("expected no submission on shift-enter, got %q", evt.Text)
			}
		default:
			return
		}
	}
}

func TestBuildPromptLayoutPreservesExplicitNewlines(t *testing.T) {
	layout := buildPromptLayout(">> ", "hello\nworld", len([]rune("hello\nworld")), 40)

	if len(layout.lines) != 2 {
		t.Fatalf("expected 2 prompt lines, got %#v", layout.lines)
	}
	if layout.lines[0] != ">> hello" {
		t.Fatalf("unexpected first prompt line %q", layout.lines[0])
	}
	if layout.lines[1] != "   world" {
		t.Fatalf("unexpected continuation prompt line %q", layout.lines[1])
	}
	if layout.cursorLine != 1 || layout.cursorCol != len("   world") {
		t.Fatalf("unexpected cursor position line=%d col=%d", layout.cursorLine, layout.cursorCol)
	}
}

func TestScreenControllerUpMovesWithinWrappedInputBeforeHistory(t *testing.T) {
	value := strings.Repeat("x", 100)
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     FormatInputLine(">> ", value),
		inputCursor:   len([]rune(value)),
		history:       []string{"from-history"},
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'A'})

	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != value {
		t.Fatalf("expected wrapped up-arrow to keep current input, got %q", got)
	}
	if screen.historyIndex != -1 {
		t.Fatalf("expected wrapped up-arrow to stay out of history, got historyIndex=%d", screen.historyIndex)
	}
	if screen.inputCursor >= len([]rune(value)) {
		t.Fatalf("expected wrapped up-arrow to move cursor within input, got cursor=%d", screen.inputCursor)
	}
}
