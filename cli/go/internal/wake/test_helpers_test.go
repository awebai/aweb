package wake

import (
	"strings"
	"time"
)

func at(seconds int) time.Time {
	return time.Unix(int64(seconds), 0).UTC()
}

func (l *logCapture) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
