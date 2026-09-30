package main

import (
	"sync"
)

// a Target to be checked
type Target struct {
	domain  string
	ns      string
	ns_root string
	status  string
	vuln    bool
}

// a Job derived from user input
type Job struct {
	domain string
}

// Keeps track if we've seen domains
type Container struct {
	mu   sync.Mutex
	seen map[string]bool
}

// markSeen records domain and reports whether it was new. The check and the
// mark happen under one lock: as separate calls, several workers could each
// see the domain as unseen and all go on to check it, which is exactly what
// happened when one trace produced the same nameserver domain several times.
func (c *Container) markSeen(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[domain] {
		return false
	}
	c.seen[domain] = true
	return true
}
