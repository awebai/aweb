package run

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

type ScreenController struct {
	inputFile   *os.File
	outputFile  *os.File
	promptLabel string

	mu            sync.Mutex
	lines         []string
	current       string
	statusLine    string
	inputLine     string
	inputCursor   int
	pending       bool
	active        bool
	busy          bool
	spinnerFrame  int
	exitConfirm   bool
	history       []string
	historyIndex  int
	historyDraft  string
	desiredColumn int
	pasting       bool

	events chan ControlEvent
	doneCh chan error

	cancelReader     cancelreader.CancelReader
	rawState         *term.State
	spinnerStop      chan struct{}
	spinnerDone      chan struct{}
	footerLines      int
	footerCursorLine int
	footerCursorCol  int
	styles           screenStyles
}

var _ UI = (*ScreenController)(nil)

type screenStyles struct {
	prompt    lipgloss.Style
	separator lipgloss.Style
	tool      lipgloss.Style
	toolMuted lipgloss.Style
	comms     lipgloss.Style
	result    lipgloss.Style
	done      lipgloss.Style
	info      lipgloss.Style
	status    lipgloss.Style
	hint      lipgloss.Style
}

const screenFooterBaseLines = 3

var screenSpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func NewScreenController(in io.Reader, out io.Writer) *ScreenController {
	inputFile, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(inputFile.Fd())) {
		return nil
	}

	outputFile, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(outputFile.Fd())) {
		return nil
	}

	return &ScreenController{
		inputFile:     inputFile,
		outputFile:    outputFile,
		promptLabel:   DefaultInputPromptLabel,
		events:        make(chan ControlEvent, 64),
		inputLine:     DefaultInputPromptLabel,
		historyIndex:  -1,
		desiredColumn: -1,
		styles:        newScreenStyles(),
	}
}

func (s *ScreenController) Start() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return nil
	}
	if strings.TrimSpace(s.promptLabel) == "" {
		s.promptLabel = DefaultInputPromptLabel
	}
	if s.inputLine == "" {
		s.inputLine = s.promptLabel
	}

	cancelReader, err := cancelreader.NewReader(s.inputFile)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	rawState, err := term.MakeRaw(int(s.inputFile.Fd()))
	if err != nil {
		s.mu.Unlock()
		_ = cancelReader.Close()
		return err
	}

	s.active = true
	s.busy = false
	s.spinnerFrame = 0
	s.pasting = false
	s.styles = newScreenStyles()
	s.cancelReader = cancelReader
	s.rawState = rawState
	fmt.Fprint(s.outputFile, "\033[?2004h")
	doneCh := make(chan error, 1)
	spinnerStop := make(chan struct{})
	spinnerDone := make(chan struct{})
	s.doneCh = doneCh
	s.spinnerStop = spinnerStop
	s.spinnerDone = spinnerDone
	s.renderFooterLocked()
	s.mu.Unlock()

	go func() {
		err := s.runInlineInputLoop(cancelReader)
		doneCh <- err
	}()
	go s.runSpinnerLoop(spinnerStop, spinnerDone)

	return nil
}

func (s *ScreenController) Stop() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil
	}
	s.active = false
	cancelReader := s.cancelReader
	doneCh := s.doneCh
	rawState := s.rawState
	spinnerStop := s.spinnerStop
	spinnerDone := s.spinnerDone
	s.cancelReader = nil
	s.rawState = nil
	s.doneCh = nil
	s.spinnerStop = nil
	s.spinnerDone = nil
	s.pending = false
	s.busy = false
	s.mu.Unlock()

	if cancelReader != nil {
		cancelReader.Cancel()
		_ = cancelReader.Close()
	}

	var loopErr error
	if doneCh != nil {
		select {
		case loopErr = <-doneCh:
		case <-time.After(2 * time.Second):
		}
	}
	if spinnerStop != nil {
		close(spinnerStop)
	}
	if spinnerDone != nil {
		select {
		case <-spinnerDone:
		case <-time.After(2 * time.Second):
		}
	}

	s.mu.Lock()
	s.teardownFooterLocked()
	s.pasting = false
	s.mu.Unlock()

	if s.outputFile != nil {
		fmt.Fprint(s.outputFile, "\033[?2004l")
	}
	if rawState != nil {
		if err := term.Restore(int(s.inputFile.Fd()), rawState); err != nil && loopErr == nil {
			loopErr = err
		}
	}

	return loopErr
}

func (s *ScreenController) Events() <-chan ControlEvent {
	if s == nil {
		return nil
	}
	return s.events
}

func (s *ScreenController) HasPendingInput() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

func (s *ScreenController) AppendText(text string) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	text = strings.ReplaceAll(text, "\r", "")
	parts := strings.Split(text, "\n")
	if len(parts) == 1 {
		s.current += parts[0]
		s.renderFooterLocked()
		return
	}

	completed := make([]string, 0, len(parts)-1)
	completed = append(completed, s.current+parts[0])
	completed = append(completed, parts[1:len(parts)-1]...)
	s.current = parts[len(parts)-1]
	s.lines = append(s.lines, completed...)

	if s.active {
		s.clearFooterLocked()
		for _, line := range completed {
			s.printOutputLineLocked(line)
		}
		s.renderFooterLocked()
		return
	}

	for _, line := range completed {
		fmt.Fprintln(s.outputFile, styleScreenLine(line, s.styles))
	}
}

func (s *ScreenController) AppendLine(line string) {
	s.AppendText(line + "\n")
}

func (s *ScreenController) SetInputLine(line string) {
	if s == nil {
		return
	}

	value := InputValueFromLine(line, s.promptLabel)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = value != ""
	s.inputLine = FormatInputLine(s.promptLabel, value)
	s.inputCursor = utf8.RuneCountInString(value)
	s.desiredColumn = -1
	s.historyIndex = -1
	s.renderFooterLocked()
}

func (s *ScreenController) ClearInputLine() {
	if s == nil {
		return
	}
	s.SetInputLine(s.promptLabel)
}

func (s *ScreenController) SetStatusLine(line string) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.statusLine = line
	s.renderFooterLocked()
}

func (s *ScreenController) SetBusy(active bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy == active {
		return
	}
	s.busy = active
	if !active {
		s.spinnerFrame = 0
	}
	s.renderFooterLocked()
}

func (s *ScreenController) ClearStatusLine() {
	s.SetStatusLine("")
}

func (s *ScreenController) SetExitConfirmation(active bool) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.exitConfirm = active
	s.renderFooterLocked()
}

func (s *ScreenController) SetPromptLabel(label string) {
	if s == nil {
		return
	}
	if strings.TrimSpace(label) == "" {
		label = DefaultInputPromptLabel
	}

	s.mu.Lock()
	s.promptLabel = label
	value := InputValueFromLine(s.inputLine, s.promptLabel)
	s.inputLine = FormatInputLine(label, value)
	s.inputCursor = utf8.RuneCountInString(value)
	s.desiredColumn = -1
	s.renderFooterLocked()
	s.mu.Unlock()
}

func (s *ScreenController) HasActiveProgram() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *ScreenController) runInlineInputLoop(reader cancelreader.CancelReader) error {
	bufReader := bufio.NewReader(reader)
	buf := make([]byte, 64)
	for {
		n, err := bufReader.Read(buf)
		if n > 0 {
			s.handleInlineInput(buf[:n])
		}
		if err == nil {
			continue
		}
		if errors.Is(err, cancelreader.ErrCanceled) || errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

func (s *ScreenController) handleInlineInput(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(data); {
		// Bracketed paste: ESC[200~ starts paste, ESC[201~ ends it.
		// The 6-byte sequence must arrive in a single read buffer; if
		// split across calls the bytes fall through as normal input.
		// In practice bufio's 4096-byte buffer prevents this.
		if i+5 < len(data) && data[i] == 0x1b && data[i+1] == '[' && data[i+2] == '2' && data[i+3] == '0' {
			if data[i+4] == '0' && data[i+5] == '~' {
				s.pasting = true
				i += 6
				continue
			}
			if data[i+4] == '1' && data[i+5] == '~' {
				s.pasting = false
				i += 6
				continue
			}
		}

		b := data[i]

		if s.pasting {
			if b == '\r' {
				i++
				continue
			}
			if b == '\n' {
				s.handleInlineRuneLocked('\n')
				i++
				continue
			}
			if b < 0x20 {
				i++
				continue
			}
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size == 1 {
				r = rune(b)
			}
			s.handleInlineRuneLocked(r)
			i += size
			continue
		}

		switch b {
		case 0x03:
			if s.exitConfirm {
				s.handleExitConfirmed()
			} else {
				s.handleInterruptRequested()
			}
			i++
		case 0x04:
			if s.exitConfirm {
				s.handleExitConfirmed()
			} else {
				s.handleExitPromptRequested()
			}
			i++
		case '\r', '\n':
			s.handleInlineSubmitLocked()
			i++
		case 0x7f, 0x08:
			s.handleInlineBackspaceLocked()
			i++
		case 0x1b:
			if i+2 < len(data) && data[i+1] == '[' {
				switch data[i+2] {
				case 'A':
					s.handleInlineUpLocked()
					i += 3
					continue
				case 'B':
					s.handleInlineDownLocked()
					i += 3
					continue
				case 'C':
					s.handleInlineRightLocked()
					i += 3
					continue
				case 'D':
					s.handleInlineLeftLocked()
					i += 3
					continue
				case 'H':
					s.handleInlineHomeLocked()
					i += 3
					continue
				case 'F':
					s.handleInlineEndLocked()
					i += 3
					continue
				case '3', '5', '6':
					if i+3 < len(data) && data[i+3] == '~' {
						i += 4
						continue
					}
				}
			}
			s.handleInlineEscapeLocked()
			i++
		default:
			if b < 0x20 {
				i++
				continue
			}
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size == 1 {
				r = rune(b)
			}
			s.handleInlineRuneLocked(r)
			i += size
		}
	}
}

func (s *ScreenController) handleInlineEscapeLocked() {
	if !s.exitConfirm {
		return
	}
	s.exitConfirm = false
	s.emit(ControlEvent{Type: ControlExitCancel})
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineRuneLocked(r rune) {
	if s.exitConfirm {
		switch r {
		case 'y', 'Y':
			s.handleExitConfirmed()
		default:
			s.exitConfirm = false
			s.emit(ControlEvent{Type: ControlExitCancel})
		}
		s.renderFooterLocked()
		return
	}

	value := InputValueFromLine(s.inputLine, s.promptLabel)
	wasPending := s.pending
	runes := []rune(value)
	if s.inputCursor < 0 {
		s.inputCursor = 0
	}
	if s.inputCursor > len(runes) {
		s.inputCursor = len(runes)
	}
	runes = append(runes[:s.inputCursor], append([]rune{r}, runes[s.inputCursor:]...)...)
	value = string(runes)
	s.inputCursor++
	s.pending = value != ""
	s.inputLine = FormatInputLine(s.promptLabel, value)
	s.desiredColumn = -1
	s.historyIndex = -1
	if !wasPending && value != "" {
		s.emit(ControlEvent{Type: ControlTypingStarted})
	}
	s.emit(ControlEvent{Type: ControlBufferUpdated, Text: value})
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineBackspaceLocked() {
	if s.exitConfirm {
		s.exitConfirm = false
		s.emit(ControlEvent{Type: ControlExitCancel})
		s.renderFooterLocked()
		return
	}

	value := InputValueFromLine(s.inputLine, s.promptLabel)
	if value == "" || s.inputCursor <= 0 {
		return
	}
	runes := []rune(value)
	if s.inputCursor > len(runes) {
		s.inputCursor = len(runes)
	}
	runes = append(runes[:s.inputCursor-1], runes[s.inputCursor:]...)
	s.inputCursor--
	value = string(runes)
	s.pending = value != ""
	s.inputLine = FormatInputLine(s.promptLabel, value)
	s.desiredColumn = -1
	s.historyIndex = -1
	s.emit(ControlEvent{Type: ControlBufferUpdated, Text: value})
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineSubmitLocked() {
	if s.exitConfirm {
		s.exitConfirm = false
		s.emit(ControlEvent{Type: ControlExitCancel})
		s.renderFooterLocked()
		return
	}

	value := InputValueFromLine(s.inputLine, s.promptLabel)
	s.pasting = false
	s.pending = false
	s.inputLine = s.promptLabel
	s.inputCursor = 0
	s.desiredColumn = -1
	s.historyIndex = -1
	s.emit(ControlEvent{Type: ControlBufferUpdated, Text: ""})
	s.renderFooterLocked()
	if strings.TrimSpace(value) == "" {
		return
	}
	s.appendHistoryLocked(value)
	s.emit(ParseControlSubmission(value))
}

func (s *ScreenController) terminalWidthLocked() int {
	if s.outputFile == nil {
		return 80
	}
	width, _, err := term.GetSize(int(s.outputFile.Fd()))
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

func (s *ScreenController) clearFooterLocked() {
	if !s.active || s.footerLines <= 0 {
		return
	}
	fmt.Fprint(s.outputFile, "\r")
	if s.footerCursorLine > 0 {
		fmt.Fprintf(s.outputFile, "\033[%dA", s.footerCursorLine)
	}
	fmt.Fprint(s.outputFile, "\033[J")
	s.footerLines = 0
	s.footerCursorLine = 0
	s.footerCursorCol = 0
}

func (s *ScreenController) renderFooterLocked() {
	if !s.active {
		return
	}

	layout := s.renderFooterLayoutLocked(s.terminalWidthLocked())
	s.clearFooterLocked()
	if len(layout.lines) == 0 {
		return
	}
	writeScreenLines(s.outputFile, layout.lines)
	s.footerLines = len(layout.lines)
	s.footerCursorLine = layout.cursorLine
	s.footerCursorCol = layout.cursorCol
	if s.footerLines-1 > s.footerCursorLine {
		fmt.Fprintf(s.outputFile, "\033[%dA", s.footerLines-1-s.footerCursorLine)
	}
	fmt.Fprint(s.outputFile, "\r")
	if s.footerCursorCol > 0 {
		fmt.Fprintf(s.outputFile, "\033[%dC", s.footerCursorCol)
	}
}

func (s *ScreenController) renderFooterLinesLocked(width int) []string {
	return s.renderFooterLayoutLocked(width).lines
}

func (s *ScreenController) renderFooterLayoutLocked(width int) promptLayout {
	currentLines := s.renderCurrentLinesLocked(width)
	lines := append([]string{}, currentLines...)
	spacerLines := 0
	if len(s.lines) > 0 || len(currentLines) > 0 {
		lines = append(lines, "")
		spacerLines = 1
	}
	prompt := buildPromptLayout(s.promptLabel, InputValueFromLine(s.inputLine, s.promptLabel), s.inputCursor, width)
	lines = append(lines, prompt.lines...)
	lines = append(lines, "")
	lines = append(lines, s.renderStatusLineLocked(width))
	prompt.lines = lines
	prompt.cursorLine += len(currentLines) + spacerLines
	return prompt
}

func (s *ScreenController) renderCurrentLinesLocked(width int) []string {
	if s.current == "" {
		return nil
	}
	return appendWrappedStyledScreenLine(nil, s.current, width, s.styles)
}

func (s *ScreenController) renderStatusLineLocked(width int) string {
	text := strings.TrimSpace(s.statusLine)
	if s.busy {
		frame := screenSpinnerFrames[s.spinnerFrame%len(screenSpinnerFrames)]
		if text == "" {
			text = frame + " working"
		} else {
			text = frame + " " + text
		}
	}
	if text != "" {
		text = truncateText(text, max(1, width-2))
	}
	return s.styles.status.Width(max(1, width)).Render(text)
}

func (s *ScreenController) printOutputLineLocked(line string) {
	lines := appendWrappedStyledScreenLine(nil, line, s.terminalWidthLocked(), s.styles)
	lines = append(lines, "")
	writeScreenLines(s.outputFile, lines)
}

func (s *ScreenController) teardownFooterLocked() {
	current := s.current
	s.current = ""
	s.clearFooterLocked()
	if current != "" {
		s.printOutputLineLocked(current)
	}
	if current != "" || len(s.lines) > 0 {
		writeScreenLines(s.outputFile, []string{""})
	}
}

func (s *ScreenController) handleInlineLeftLocked() {
	if s.exitConfirm {
		return
	}
	if s.inputCursor <= 0 {
		return
	}
	s.inputCursor--
	s.desiredColumn = -1
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineRightLocked() {
	if s.exitConfirm {
		return
	}
	value := []rune(InputValueFromLine(s.inputLine, s.promptLabel))
	if s.inputCursor >= len(value) {
		return
	}
	s.inputCursor++
	s.desiredColumn = -1
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineHomeLocked() {
	if s.exitConfirm {
		return
	}
	s.inputCursor = 0
	s.desiredColumn = 0
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineEndLocked() {
	if s.exitConfirm {
		return
	}
	value := []rune(InputValueFromLine(s.inputLine, s.promptLabel))
	s.inputCursor = len(value)
	s.desiredColumn = -1
	s.renderFooterLocked()
}

func (s *ScreenController) handleInlineUpLocked() {
	if s.exitConfirm {
		return
	}
	value := InputValueFromLine(s.inputLine, s.promptLabel)
	layout := buildPromptLayout(s.promptLabel, value, s.inputCursor, s.terminalWidthLocked())
	if layout.cursorLine > 0 {
		s.moveCursorVerticalLocked(layout, -1)
		s.renderFooterLocked()
		return
	}
	if s.navigateHistoryLocked(-1) {
		s.renderFooterLocked()
	}
}

func (s *ScreenController) handleInlineDownLocked() {
	if s.exitConfirm {
		return
	}
	value := InputValueFromLine(s.inputLine, s.promptLabel)
	layout := buildPromptLayout(s.promptLabel, value, s.inputCursor, s.terminalWidthLocked())
	if layout.cursorLine < len(layout.visualLines)-1 {
		s.moveCursorVerticalLocked(layout, 1)
		s.renderFooterLocked()
		return
	}
	if s.navigateHistoryLocked(1) {
		s.renderFooterLocked()
	}
}

func (s *ScreenController) moveCursorVerticalLocked(layout promptLayout, delta int) {
	current := layout.cursorLine
	target := current + delta
	if target < 0 || target >= len(layout.visualLines) {
		return
	}
	if s.desiredColumn < 0 {
		s.desiredColumn = max(0, layout.cursorCol-layout.prefixWidth)
	}
	s.inputCursor = layout.cursorIndexForLineColumn(target, s.desiredColumn)
}

func (s *ScreenController) navigateHistoryLocked(direction int) bool {
	if len(s.history) == 0 {
		return false
	}
	value := InputValueFromLine(s.inputLine, s.promptLabel)
	if direction < 0 {
		if s.historyIndex == -1 {
			s.historyDraft = value
			s.historyIndex = len(s.history) - 1
		} else if s.historyIndex > 0 {
			s.historyIndex--
		} else {
			return false
		}
	} else {
		if s.historyIndex == -1 {
			return false
		}
		if s.historyIndex < len(s.history)-1 {
			s.historyIndex++
		} else {
			s.historyIndex = -1
			s.setInputValueLocked(s.historyDraft)
			return true
		}
	}
	s.setInputValueLocked(s.history[s.historyIndex])
	return true
}

func (s *ScreenController) setInputValueLocked(value string) {
	s.pending = value != ""
	s.inputLine = FormatInputLine(s.promptLabel, value)
	s.inputCursor = utf8.RuneCountInString(value)
	s.desiredColumn = -1
	s.emit(ControlEvent{Type: ControlBufferUpdated, Text: value})
}

func (s *ScreenController) appendHistoryLocked(value string) {
	if value == "" {
		return
	}
	if n := len(s.history); n > 0 && s.history[n-1] == value {
		return
	}
	s.history = append(s.history, value)
}

func writeScreenLines(w io.Writer, lines []string) {
	if len(lines) == 0 {
		return
	}
	_, _ = io.WriteString(w, "\r")
	for i, line := range lines {
		if i > 0 {
			_, _ = io.WriteString(w, "\r\n")
		}
		_, _ = io.WriteString(w, line)
	}
}

func (s *ScreenController) emit(event ControlEvent) {
	select {
	case s.events <- event:
	default:
	}
}

func (s *ScreenController) runSpinnerLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.active && s.busy {
				s.spinnerFrame = (s.spinnerFrame + 1) % len(screenSpinnerFrames)
				s.renderFooterLocked()
			}
			s.mu.Unlock()
		}
	}
}

func (s *ScreenController) handleInterruptRequested() {
	s.emit(ControlEvent{Type: ControlInterrupt})
}

func (s *ScreenController) handleExitPromptRequested() {
	s.emit(ControlEvent{Type: ControlExitPrompt})
}

func (s *ScreenController) handleExitConfirmed() {
	s.emit(ControlEvent{Type: ControlExitConfirm})
}

func newScreenStyles() screenStyles {
	return screenStyles{
		prompt:    lipgloss.NewStyle().Bold(true),
		separator: lipgloss.NewStyle(),
		tool:      lipgloss.NewStyle(),
		toolMuted: lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "242", Dark: "244"}),
		comms:     lipgloss.NewStyle().Bold(true),
		result:    lipgloss.NewStyle(),
		done:      lipgloss.NewStyle(),
		info:      lipgloss.NewStyle(),
		status: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "236", Dark: "252"}).
			Background(lipgloss.AdaptiveColor{Light: "252", Dark: "236"}).
			Padding(0, 1),
		hint: lipgloss.NewStyle(),
	}
}

type promptVisualLine struct {
	start int
	end   int
	text  string
}

type promptCursorPos struct {
	line int
	col  int
}

type promptLayout struct {
	lines       []string
	visualLines []promptVisualLine
	positions   []promptCursorPos
	cursorLine  int
	cursorCol   int
	prefixWidth int
}

func buildPromptLayout(promptLabel string, value string, cursor int, width int) promptLayout {
	if strings.TrimSpace(promptLabel) == "" {
		promptLabel = DefaultInputPromptLabel
	}
	if width <= 0 {
		width = lipgloss.Width(promptLabel) + max(1, lipgloss.Width(value))
	}

	promptWidth := lipgloss.Width(promptLabel)

	continuation := strings.Repeat(" ", promptWidth)
	runes := []rune(strings.ReplaceAll(value, "\n", " "))
	if cursor < 0 {
		cursor = 0
	}
	if cursor > len(runes) {
		cursor = len(runes)
	}

	layout := promptLayout{
		prefixWidth: promptWidth,
		positions:   make([]promptCursorPos, len(runes)+1),
	}

	lineStarts := []int{0}
	linePrefixes := []string{promptLabel}
	currentLine := 0
	currentCol := promptWidth
	layout.positions[0] = promptCursorPos{line: 0, col: promptWidth}

	for i, r := range runes {
		runeWidth := lipgloss.Width(string(r))
		if runeWidth <= 0 {
			runeWidth = 1
		}
		if currentCol+runeWidth > width && currentCol > promptWidth {
			lineStarts = append(lineStarts, i)
			linePrefixes = append(linePrefixes, continuation)
			currentLine++
			currentCol = promptWidth
			layout.positions[i] = promptCursorPos{line: currentLine, col: currentCol}
		}
		currentCol += runeWidth
		layout.positions[i+1] = promptCursorPos{line: currentLine, col: currentCol}
	}

	layout.visualLines = make([]promptVisualLine, 0, len(lineStarts))
	layout.lines = make([]string, 0, len(lineStarts))
	for i, start := range lineStarts {
		end := len(runes)
		if i+1 < len(lineStarts) {
			end = lineStarts[i+1]
		}
		text := string(runes[start:end])
		layout.visualLines = append(layout.visualLines, promptVisualLine{start: start, end: end, text: text})
		layout.lines = append(layout.lines, linePrefixes[i]+text)
	}
	if len(layout.lines) == 0 {
		layout.lines = []string{promptLabel}
		layout.visualLines = []promptVisualLine{{start: 0, end: 0, text: ""}}
		layout.positions = []promptCursorPos{{line: 0, col: promptWidth}}
	}

	layout.cursorLine = layout.positions[cursor].line
	layout.cursorCol = layout.positions[cursor].col
	return layout
}

func (l promptLayout) cursorIndexForLineColumn(targetLine int, targetColumn int) int {
	if targetLine < 0 {
		targetLine = 0
	}
	if targetLine >= len(l.visualLines) {
		targetLine = len(l.visualLines) - 1
	}
	if targetColumn < 0 {
		targetColumn = 0
	}

	line := l.visualLines[targetLine]
	best := line.start
	bestDelta := int(^uint(0) >> 1)
	for idx := line.start; idx <= line.end; idx++ {
		pos := l.positions[idx]
		column := max(0, pos.col-l.prefixWidth)
		delta := abs(column - targetColumn)
		if delta < bestDelta || (delta == bestDelta && idx > best) {
			best = idx
			bestDelta = delta
		}
		if column >= targetColumn {
			break
		}
	}
	return best
}

func appendScreenText(lines *[]string, current *string, text string) {
	text = strings.ReplaceAll(text, "\r", "")
	parts := strings.Split(text, "\n")
	if len(parts) == 1 {
		*current += parts[0]
		return
	}

	*current += parts[0]
	*lines = append(*lines, *current)
	for _, part := range parts[1 : len(parts)-1] {
		*lines = append(*lines, part)
	}
	*current = parts[len(parts)-1]
}

func appendWrappedStyledScreenLine(lines []string, line string, width int, styles screenStyles) []string {
	kind := screenLineStyleKind(line)
	for idx, wrapped := range wrapScreenLine(line, width) {
		lines = append(lines, styleWrappedScreenLine(wrapped, kind, idx, styles))
	}
	return lines
}

func wrapScreenLine(line string, width int) []string {
	if width <= 0 || lipgloss.Width(line) <= width {
		return []string{line}
	}

	indent := continuationIndent(line)
	tokens := splitWrapTokens(line)
	if len(tokens) == 0 {
		return []string{line}
	}

	lines := make([]string, 0, 4)
	current := ""
	lineIndent := ""

	for _, token := range tokens {
		if current == "" {
			trimmed := strings.TrimLeft(token, " ")
			if trimmed == "" {
				current = indent
			} else if indent != "" {
				current = indent + trimmed
			} else {
				current = trimmed
			}
			continue
		}

		candidate := current + token
		if lipgloss.Width(candidate) <= width {
			current = candidate
			continue
		}

		lines = append(lines, strings.TrimRight(current, " "))
		if lineIndent == "" {
			lineIndent = indent
			if lineIndent == "" {
				lineIndent = "  "
			}
		}

		trimmed := strings.TrimLeft(token, " ")
		if trimmed == "" {
			current = lineIndent
			continue
		}
		current = lineIndent + trimmed
		for lipgloss.Width(current) > width && width > lipgloss.Width(lineIndent) {
			available := max(1, width-lipgloss.Width(lineIndent))
			chunk, rest := splitWrapChunk(strings.TrimPrefix(current, lineIndent), available)
			lines = append(lines, lineIndent+chunk)
			if rest == "" {
				current = lineIndent
				break
			}
			current = lineIndent + rest
		}
	}

	if strings.TrimSpace(current) != "" {
		lines = append(lines, strings.TrimRight(current, " "))
	}
	if len(lines) == 0 {
		return []string{line}
	}
	return lines
}

func splitWrapTokens(line string) []string {
	parts := strings.SplitAfter(line, " ")
	if len(parts) == 0 {
		return []string{line}
	}
	return parts
}

func splitWrapChunk(s string, width int) (string, string) {
	if lipgloss.Width(s) <= width {
		return s, ""
	}
	runes := []rune(s)
	if width >= len(runes) {
		return s, ""
	}
	return string(runes[:width]), strings.TrimLeft(string(runes[width:]), " ")
}

func leadingWhitespace(s string) string {
	idx := 0
	for idx < len(s) && (s[idx] == ' ' || s[idx] == '\t') {
		idx++
	}
	return s[:idx]
}

func continuationIndent(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "<- ") || strings.HasPrefix(trimmed, "-> ") {
		return leadingWhitespace(line) + "   "
	}
	if strings.HasPrefix(trimmed, ">_ ") {
		return leadingWhitespace(line) + "   "
	}
	return leadingWhitespace(line)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func styleScreenLine(line string, styles screenStyles) string {
	return styleWrappedScreenLine(line, screenLineStyleKind(line), 0, styles)
}

func styleWrappedScreenLine(line string, kind string, wrapIndex int, styles screenStyles) string {
	switch kind {
	case "prompt":
		return styles.prompt.Render(line)
	case "separator":
		return styles.separator.Render(line)
	case "tool":
		if wrapIndex > 0 {
			return styles.toolMuted.Render(line)
		}
		return styleScreenToolLine(line, styles)
	case "tool_detail":
		return styles.toolMuted.Render(line)
	case "comms":
		return styleScreenCommLine(line, styles)
	case "result":
		return styles.result.Render(line)
	case "done":
		return styles.done.Render(line)
	case "info":
		return styles.info.Render(line)
	case "hint":
		return styles.hint.Render(line)
	default:
		return styleScreenToolClosingParen(line, styles)
	}
}

func styleScreenToolLine(line string, styles screenStyles) string {
	const prefix = ">_ "
	if !strings.HasPrefix(line, prefix) {
		return styles.tool.Render(line)
	}

	rest := line[len(prefix):]
	if rest == "" {
		return styles.tool.Render(line)
	}

	headEnd := len(rest)
	if idx := strings.Index(rest, "("); idx >= 0 {
		headEnd = idx
	} else if idx := strings.Index(rest, " "); idx >= 0 {
		headEnd = idx
	}
	if headEnd <= 0 || headEnd >= len(rest) {
		return styles.tool.Render(line)
	}

	head := prefix + rest[:headEnd]
	tail := rest[headEnd:]
	return styles.tool.Render(head) + styles.toolMuted.Render(tail)
}

func styleScreenToolClosingParen(line string, styles screenStyles) string {
	trimmed := strings.TrimRight(line, " ")
	if trimmed == "" || !strings.HasSuffix(trimmed, ")") {
		return line
	}
	suffixStart := len(trimmed) - 1
	return line[:suffixStart] + styles.tool.Render(")") + line[len(trimmed):]
}

func styleScreenCommLine(line string, styles screenStyles) string {
	indent := leadingWhitespace(line)
	trimmed := strings.TrimPrefix(line, indent)
	if !strings.HasPrefix(trimmed, "<- ") && !strings.HasPrefix(trimmed, "-> ") {
		return line
	}

	marker := trimmed[:3]
	rest := trimmed[3:]
	aliasEnd := len(rest)
	for i, r := range rest {
		if r == ' ' || r == ':' {
			aliasEnd = i
			break
		}
	}
	head := marker + rest[:aliasEnd]
	tail := rest[aliasEnd:]
	return indent + styles.comms.Render(head) + tail
}

func screenLineStyleKind(line string) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "────"):
		return "separator"
	case strings.HasPrefix(trimmed, "> "):
		return "prompt"
	case strings.HasPrefix(trimmed, ">_ "):
		return "tool"
	case strings.HasPrefix(line, "  ->"), strings.HasPrefix(line, "  ="):
		return "result"
	case strings.HasPrefix(trimmed, "<- ") || strings.HasPrefix(trimmed, "-> "):
		return "comms"
	case strings.HasPrefix(trimmed, "->"):
		return "result"
	case isToolDetailLine(line):
		return "tool_detail"
	case strings.HasPrefix(trimmed, "done"):
		return "done"
	case strings.HasPrefix(trimmed, "info:"):
		return "info"
	case strings.HasPrefix(trimmed, "type /"):
		return "hint"
	default:
		return "plain"
	}
}

func isToolDetailLine(line string) bool {
	indent := leadingWhitespace(line)
	if len(indent) < 2 {
		return false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, ">") || strings.HasPrefix(trimmed, "<-") || strings.HasPrefix(trimmed, "->") {
		return false
	}
	return strings.Contains(trimmed, "=")
}
