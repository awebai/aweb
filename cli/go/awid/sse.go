package awid

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// SSEEvent is a single Server-Sent Event.
type SSEEvent struct {
	Event string
	Data  string
	ID    string
	Retry int
}

// SSEStream decodes a text/event-stream body.
//
// It is intentionally minimal; callers can unmarshal Data as JSON based on Event.
type SSEStream struct {
	body io.ReadCloser
	r    *bufio.Reader
	// onComment, when set, is called for every comment line read.
	onComment func()
}

func NewSSEStream(body io.ReadCloser) *SSEStream {
	return &SSEStream{body: body, r: bufio.NewReader(body)}
}

func (s *SSEStream) Close() error {
	if s.body == nil {
		return nil
	}
	return s.body.Close()
}

// Next reads the next SSE event. It returns io.EOF when the stream ends.
func (s *SSEStream) Next() (*SSEEvent, error) {
	var eventName string
	var dataLines []string
	var eventID string
	retry := -1

	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			if err == io.EOF && (eventName != "" || len(dataLines) > 0) {
				return &SSEEvent{
					Event: eventName,
					Data:  strings.Join(dataLines, "\n"),
					ID:    eventID,
					Retry: retry,
				}, nil
			}
			return nil, err
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if eventName == "" && len(dataLines) == 0 {
				continue
			}
			return &SSEEvent{
				Event: eventName,
				Data:  strings.Join(dataLines, "\n"),
				ID:    eventID,
				Retry: retry,
			}, nil
		}
		if strings.HasPrefix(line, ":") {
			if s.onComment != nil {
				s.onComment()
			}
			continue
		}

		field, value, ok := parseSSEField(line)
		if !ok {
			continue
		}
		switch field {
		case "event":
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		case "id":
			eventID = value
		case "retry":
			if ms, err := strconv.Atoi(value); err == nil && ms >= 0 {
				retry = ms
			}
		}
	}
}

func parseSSEField(line string) (field string, value string, ok bool) {
	field = line
	value = ""
	if idx := strings.IndexByte(line, ':'); idx >= 0 {
		field = line[:idx]
		value = line[idx+1:]
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
	}
	field = strings.TrimSpace(field)
	if field == "" {
		return "", "", false
	}
	return field, value, true
}
