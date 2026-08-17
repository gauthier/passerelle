package limits

import (
	"fmt"
	"sync"
)

type Conns struct {
	mu   sync.Mutex
	cur  map[string]int
	maxF func(userID string) int
}

func NewConns(maxF func(userID string) int) *Conns {
	return &Conns{cur: make(map[string]int), maxF: maxF}
}

func (c *Conns) Acquire(userID string) (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	max := 100
	if c.maxF != nil {
		if m := c.maxF(userID); m > 0 {
			max = m
		}
	}
	if c.cur[userID] >= max {
		return nil, fmt.Errorf("connection quota exceeded")
	}
	c.cur[userID]++
	return func() {
		c.mu.Lock()
		c.cur[userID]--
		if c.cur[userID] <= 0 {
			delete(c.cur, userID)
		}
		c.mu.Unlock()
	}, nil
}
