package ext

import "time"

// Clock wraps the Now method. Introduced to allow replacing the global state with fixed clocks to facilitate testing.
// Now returns the current time.
type Clock interface {
	Now() time.Time
}

type systemClock struct {
}

func (c *systemClock) Now() time.Time {
	return time.Now()
}

func NewSystemClock() Clock {
	return &systemClock{}
}

type fixedClock struct {
	fixedTime time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.fixedTime
}

func NewFixedClock(fixedTime time.Time) Clock {
	return &fixedClock{
		fixedTime: fixedTime,
	}
}
