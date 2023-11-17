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
	"github.com/gookit/color"
	"os"
	"sync"
)

// globals
var verbose bool
var strict bool
var concurrency int
var dnsServer string

// channels
var jobs = make(chan Job, 100)
var nxs = make(chan Target, 100)

func main() {

	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")
	flag.StringVar(&dnsServer, "d", "", "specify a custom DNS resolver address")
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

				if c.isSeen(tgt.ns_root) {
					continue
				}

				if verbose {
					fmt.Printf("%s has NS %s\n", tgt.domain, tgt.ns_root)
				}

				c.addToSeen(tgt.ns_root)
				vuln, err := isNX(&tgt)

				if err != nil {
					continue
				}
				// do i need both checks here?
				if vuln && tgt.vuln {
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
		if verbose {
			color.Red.Printf("Failed to fetch user input, please retry.\n")
		}
		os.Exit(1)
	}

	// tidy up
	close(jobs)
	tg.Wait()

	close(nxs)
	ng.Wait()

}
