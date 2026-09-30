/*
nsfckup

takes a list of domains and performs a dig domain +trace
extracts the NameServers and look for those which return an NXDOMAIN
this could indicate a possible NS takeover issue.
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/gookit/color"
)

// globals
var verbose bool
var concurrency int

// channels
var jobs = make(chan Job, 100)
var nxs = make(chan Target, 100)

// Note: on a read error the workers are left running; the process exits.

func main() {

	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&verbose, "v", false, "Get more info on attempts")

	flag.Parse()

	if concurrency < 1 {
		fmt.Fprintf(os.Stderr, "-c must be at least 1 (got %d)\n", concurrency)
		os.Exit(2)
	}

	c := Container{seen: make(map[string]bool)}

	// traceit group
	var tg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		tg.Add(1)
		go func() {
			defer tg.Done()
			for job := range jobs {
				traceIt(&job)
			}
		}()
	}

	// nx group
	var ng sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		ng.Add(1)

		go func() {
			defer ng.Done()
			for tgt := range nxs {
				if !c.markSeen(tgt.ns_root) {
					continue
				}

				if verbose {
					fmt.Fprintf(os.Stderr, "%s has NS %s\n", tgt.domain, tgt.ns_root)
				}

				vuln, err := isNX(&tgt)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "dig A %s failed: %s\n", tgt.ns_root, err)
					}
					continue
				}
				if vuln {
					if verbose {
						color.Green.Printf("%s has root domain %s from NS %s which is %s\n", tgt.domain, tgt.ns_root, tgt.ns, tgt.status)
					} else {
						fmt.Printf("%s,%s,%s,%s\n", tgt.domain, tgt.ns, tgt.ns_root, tgt.status)
					}
				}
			}
		}()
	}

	// this sends to the domains channel
	_, err := GetUserInput()
	if err != nil {
		fmt.Fprint(os.Stderr, color.Red.Sprintf("Failed to read input: %s\n", err))
		os.Exit(1)
	}

	// tidy up
	close(jobs)
	tg.Wait()

	close(nxs)
	ng.Wait()

}
