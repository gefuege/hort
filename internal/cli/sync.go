package cli

import (
	"fmt"
	"time"
)

// syncLimit bounds the automatic sync around reads and writes (contract §4):
// a slow server must not hold up a local read. Stopping is safe, all writes
// are atomic.
const syncLimit = 2 * time.Second

func limitSync[T any](limit time.Duration, run func() (T, error)) (T, error) {
	type outcome struct {
		result T
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := run()
		done <- outcome{result, err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.result, o.err
	case <-timer.C:
		var zero T
		return zero, fmt.Errorf("no answer within %s", limit)
	}
}
