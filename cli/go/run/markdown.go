package run

import (
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	glamourstyles "github.com/charmbracelet/glamour/styles"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

const (
	displayLeftMargin      = 2
	defaultDisplayWidth    = 80
	minMarkdownRenderWidth = 24
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func renderAssistantText(providerName string, text string, out io.Writer, startsAtLine bool) string {
	if strings.TrimSpace(text) == "" {
		return text
	}

	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case "codex":
		return renderCodexAssistantTextWithOptions(text, displayWidth(out), outputSupportsANSI(out), out)
	case "claude":
		return indentStreamingText(text, displayLeftMargin, startsAtLine)
	default:
		return text
	}
}

func renderCodexAssistantText(text string, width int) string {
	return renderCodexAssistantTextWithOptions(text, width, false, nil)
}

func renderCodexAssistantTextWithOptions(text string, width int, supportsANSI bool, out io.Writer) string {
	if text == "" {
		return ""
	}

	wrapWidth := max(minMarkdownRenderWidth, width-displayLeftMargin)
	style := codexMarkdownStyle(supportsANSI, out)
	renderer, err := glamour.NewTermRenderer(
		glamour.WithStyles(style),
		glamour.WithWordWrap(wrapWidth),
		glamour.WithPreservedNewLines(),
	)
	if err != nil {
		return indentDisplayText(text, displayLeftMargin)
	}

	rendered, err := renderer.Render(text)
	if err != nil {
		return indentDisplayText(text, displayLeftMargin)
	}
	return indentDisplayText(trimRenderedTrailingWhitespace(rendered), displayLeftMargin)
}

func indentDisplayText(text string, margin int) string {
	if text == "" || margin <= 0 {
		return text
	}

	prefix := strings.Repeat(" ", margin)
	hasTrailingNewline := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines[i] = prefix + line
	}
	result := strings.Join(lines, "\n")
	if hasTrailingNewline {
		result += "\n"
	}
	return result
}

func indentStreamingText(text string, margin int, startsAtLine bool) string {
	if text == "" || margin <= 0 {
		return text
	}

	prefix := strings.Repeat(" ", margin)
	var out strings.Builder
	atLineStart := startsAtLine
	for _, r := range text {
		if atLineStart && r != '\n' && r != '\r' {
			out.WriteString(prefix)
			atLineStart = false
		}
		out.WriteRune(r)
		if r == '\n' || r == '\r' {
			atLineStart = true
		}
	}
	return out.String()
}

func displayWidth(out io.Writer) int {
	file, ok := out.(*os.File)
	if !ok {
		return defaultDisplayWidth
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		return defaultDisplayWidth
	}
	return width
}

func outputSupportsANSI(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func stripANSIEscapeCodes(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
}

func codexMarkdownStyle(supportsANSI bool, out io.Writer) ansi.StyleConfig {
	var style ansi.StyleConfig
	switch {
	case !supportsANSI:
		style = glamourstyles.NoTTYStyleConfig
	case hasDarkBackground(out):
		style = glamourstyles.DarkStyleConfig
	default:
		style = glamourstyles.LightStyleConfig
	}

	// Let the loop own the left gutter and spacing; remove markdown heading markers.
	style.Document.BlockPrefix = ""
	style.Document.BlockSuffix = ""
	style.Document.Margin = uintPtr(0)
	style.H1.Prefix = ""
	style.H1.Suffix = ""
	style.H2.Prefix = ""
	style.H3.Prefix = ""
	style.H4.Prefix = ""
	style.H5.Prefix = ""
	style.H6.Prefix = ""
	return style
}

func hasDarkBackground(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return true
	}
	return termenv.NewOutput(file).HasDarkBackground()
}

var trailingWhitespacePattern = regexp.MustCompile(`([ \t]+)((?:\x1b\[[0-9;]*m)*)$`)

func trimRenderedTrailingWhitespace(text string) string {
	if text == "" {
		return ""
	}
	hasTrailingNewline := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		lines[i] = trailingWhitespacePattern.ReplaceAllString(line, "$2")
	}
	result := strings.Join(lines, "\n")
	if hasTrailingNewline {
		result += "\n"
	}
	return result
}

func uintPtr(v uint) *uint {
	return &v
}
