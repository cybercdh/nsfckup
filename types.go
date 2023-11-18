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
	// resolver string
}

// Keeps track if we've seen domains
type Container struct {
	mu   sync.Mutex
	seen map[string]bool
}
