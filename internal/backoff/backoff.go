package backoff

import (
	"math/rand"
	"time"
)

func Next(prev time.Duration) time.Duration {
	if prev < time.Second {
		prev = time.Second
	} else {
		prev *= 2
	}
	if prev > 30*time.Second {
		prev = 30 * time.Second
	}
	j := time.Duration(rand.Int63n(int64(prev/5) + 1))
	return prev - prev/10 + j
}
