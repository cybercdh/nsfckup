/*
nsfckup

takes a list of domains and performs a dig domain +trace
extracts the NameServers and look for those which return an NXDOMAIN
this could indicate a possible NS takeover issue.
*/

package main

import (
	// "bufio"
	"flag"
	"fmt"
	"github.com/gookit/color"
	"os"
	"sync"
)

type Container struct {
	mu   sync.Mutex
	seen map[string]bool
}

// globals
var verbose bool
var strict bool
var concurrency int

// channels
var domains = make(chan string)
var nxs = make(chan string)
var output = make(chan string)

func (c *Container) addToSeen(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[domain] = true
}

func (c *Container) isSeen(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// if we've seen the domain before, return true
	if _, ok := c.seen[domain]; ok {
		return true
	}
	return false
}

func main() {

	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&verbose, "v", false, "Get more info on attempts")
	flag.BoolVar(&strict, "s", false, "Be strict on CNAME, must include the target domain")

	flag.Parse()

	c := Container{
		seen: map[string]bool{"": false},
	}

	// traceit group
	var tg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		tg.Add(1)
		go func() {
			defer tg.Done()
			for domain := range domains {
				traceIt(domain)
			}
		}()
	}

	// nx group
	var ng sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		ng.Add(1)

		go func() {
			defer ng.Done()
			for nx := range nxs {

				if c.isSeen(nx) {
					if verbose {
						fmt.Printf("Seen %s\n", nx)
					}
					continue
				}

				c.addToSeen(nx)
				vuln, err := isNX(nx)

				if err != nil {
					continue
				}
				if vuln {
					output <- nx
				}
			}
		}()
	}

	// output group
	// results here are what we're interested in
	var og sync.WaitGroup
	og.Add(1)
	go func() {
		defer og.Done()
		for o := range output {
			if verbose {
				color.Green.Println(o)
			}
			fmt.Println(o)
		}
	}()

	// this sends to the domains channel
	_, err := GetUserInput()
	if err != nil {
		if verbose {
			color.Red.Printf("Failed to fetch user input, please retry.\n")
		}
		os.Exit(1)
	}

	// tidy up
	close(domains)
	tg.Wait()

	close(nxs)
	ng.Wait()

	close(output)
	og.Wait()

}
