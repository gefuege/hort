package mcp

import "time"

// SetPolling shortens the poll of the tests and returns a function that restores it.
func SetPolling(every, total time.Duration) (restore func()) {
	oldEvery, oldTotal := pollEvery, pollFor
	pollEvery, pollFor = every, total
	return func() { pollEvery, pollFor = oldEvery, oldTotal }
}
