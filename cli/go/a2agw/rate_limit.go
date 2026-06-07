package a2agw

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	windows map[string]rateWindow
}

type rateWindow struct {
	Start time.Time
	Count int
}

type rateLimitSpec struct {
	Count  int
	Window time.Duration
}

func newRateLimiter(now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{now: now, windows: map[string]rateWindow{}}
}

func (l *rateLimiter) allow(key, raw string) (bool, error) {
	spec, err := parseRateLimit(raw)
	if err != nil || spec.Count <= 0 {
		return err == nil, err
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.windows[key]
	if window.Start.IsZero() || !now.Before(window.Start.Add(spec.Window)) {
		window = rateWindow{Start: now}
	}
	if window.Count >= spec.Count {
		l.windows[key] = window
		return false, nil
	}
	window.Count++
	l.windows[key] = window
	return true, nil
}

func parseRateLimit(raw string) (rateLimitSpec, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return rateLimitSpec{}, nil
	}
	parts := strings.Split(raw, "/")
	if len(parts) != 2 {
		return rateLimitSpec{}, fmt.Errorf("rate limit must be N/s, N/m, or N/h")
	}
	count, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || count <= 0 {
		return rateLimitSpec{}, fmt.Errorf("rate limit count must be positive")
	}
	switch strings.TrimSpace(parts[1]) {
	case "s", "sec", "second":
		return rateLimitSpec{Count: count, Window: time.Second}, nil
	case "m", "min", "minute":
		return rateLimitSpec{Count: count, Window: time.Minute}, nil
	case "h", "hour":
		return rateLimitSpec{Count: count, Window: time.Hour}, nil
	default:
		return rateLimitSpec{}, fmt.Errorf("rate limit window must be s, m, or h")
	}
}
