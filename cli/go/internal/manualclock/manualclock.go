// Package manualclock is a clock that moves only when a test moves it. It
// supplies the time, timer and random source the event stream policy takes as
// dependencies, so tests of minutes-long delays run in milliseconds.
package manualclock

import (
	"sort"
	"sync"
	"time"
)

// Clock is a manually advanced clock. The zero value is not usable; use New.
type Clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*timer
	random float64
}

type timer struct {
	at    time.Time
	fired chan time.Time
}

// New returns a clock stopped at start.
func New(start time.Time) *Clock {
	return &Clock{now: start}
}

// Now reports the clock's current time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// SetRandom sets the value Random returns. It must be in [0, 1).
func (c *Clock) SetRandom(value float64) {
	c.mu.Lock()
	c.random = value
	c.mu.Unlock()
}

// Random returns the value set by SetRandom, initially 0.
func (c *Clock) Random() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.random
}

// Timer returns a channel that receives once the clock has advanced by d, and
// a function that withdraws the timer.
func (c *Clock) Timer(d time.Duration) (<-chan time.Time, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &timer{at: c.now.Add(d), fired: make(chan time.Time, 1)}
	if d <= 0 {
		t.fired <- c.now
		return t.fired, func() {}
	}
	c.timers = append(c.timers, t)
	return t.fired, func() { c.withdraw(t) }
}

func (c *Clock) withdraw(t *timer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, pending := range c.timers {
		if pending == t {
			c.timers = append(c.timers[:i], c.timers[i+1:]...)
			return
		}
	}
}

// Advance moves the clock forward by d and fires, in order, every timer that
// has come due.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].at.Before(c.timers[j].at) })
	remaining := c.timers[:0]
	for _, t := range c.timers {
		if t.at.After(c.now) {
			remaining = append(remaining, t)
			continue
		}
		t.fired <- t.at
	}
	c.timers = remaining
}

// Timers reports how many timers are waiting to fire.
func (c *Clock) Timers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// NextTimer reports how long until the earliest waiting timer fires.
func (c *Clock) NextTimer() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) == 0 {
		return 0, false
	}
	earliest := c.timers[0].at
	for _, t := range c.timers[1:] {
		if t.at.Before(earliest) {
			earliest = t.at
		}
	}
	return earliest.Sub(c.now), true
}

// AwaitTimers blocks until exactly n timers are waiting, which is how a test
// knows the code under test has gone to sleep before it advances the clock.
// It reports false if that does not happen within a real-time bound.
func (c *Clock) AwaitTimers(n int) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.Timers() == n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return c.Timers() == n
}
