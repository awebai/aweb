package aweb

import (
	"bufio"
	"io"
	"strings"
)

// SSEEvent is a single Server-Sent Event.
type SSEEvent struct {
	Event string
	Data  string
}

// SSEStream decodes a text/event-stream body.
//
// It is intentionally minimal; callers can unmarshal Data as JSON based on Event.
type SSEStream struct {
	body io.ReadCloser
	r *bufio.Reader
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

	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			if err == io.EOF && (eventName != "" || len(dataLines) > 0) {
				return &SSEEvent{Event: eventName, Data: strings.Join(dataLines, "\n")}, nil
			}
			return nil, err
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if eventName == "" && len(dataLines) == 0 {
				continue
			}
			return &SSEEvent{Event: eventName, Data: strings.Join(dataLines, "\n")}, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			continue
		}
	}
}
