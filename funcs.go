package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

/*
traceIt
takes a domain and performs a dig domain.com +trace
sends NS's to nxs channel
*/
func traceIt(job *Job) {
	if verbose {
		fmt.Fprintf(os.Stderr, "dig %s +trace\n", job.domain)
	}

	var dig dnsutil.Dig

	rsps, err := dig.Trace(job.domain)
	if err != nil && verbose {
		// there was an issue with a nameserver, probably timing out. The
		// responses gathered before the failure are still worth checking.
		fmt.Fprintf(os.Stderr, "Tracing %s produced error: %s\n", job.domain, err)
	}

	for _, rsp := range rsps {
		if rsp.Msg == nil {
			continue
		}
		// parse each NS, extract the registrable domain
		// and send to nxs channel to check
		for _, rr := range rsp.Msg.Ns {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			svr := strings.TrimSuffix(strings.ToLower(ns.Ns), ".")
			root, ok := registrable(svr)
			if !ok {
				continue
			}
			nxs <- Target{domain: job.domain, ns: svr, ns_root: root}
		}
	}
}

// registrable returns the registrable domain (eTLD+1) of a nameserver
// hostname, e.g. ns1.example.co.uk -> example.co.uk. It replaces a parser
// that downloaded a TLD list into /tmp/.tlds on every fresh machine, ignored
// download failures, and trusted whatever was already in that world-writable
// file. The public suffix list ships with golang.org/x/net instead.
func registrable(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", false
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || root == "" {
		return "", false
	}
	return root, true
}

/*
returns true if an NXDOMAIN response is received from dig
*/
func isNX(tgt *Target) (bool, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "dig A %s\n", tgt.ns_root)
	}
	var dig dnsutil.Dig
	dig.Retry = 3

	msg, err := dig.GetMsg(dns.TypeA, tgt.ns_root)
	if err != nil {
		return false, err
	}

	// check is the NameServer returns NXDOMAIN
	status := dns.RcodeToString[msg.MsgHdr.Rcode]
	if status == "NXDOMAIN" {
		tgt.status = status
		tgt.vuln = true
		return true, nil
	}

	return false, nil
}

/*
get a list of domains from the user and send to the channel to work
*/
func GetUserInput() (bool, error) {
	seen := make(map[string]bool)

	// read from stdin or from arg
	var input io.Reader = os.Stdin
	if arg := flag.Arg(0); arg != "" {
		input = strings.NewReader(arg)
	}

	sc := bufio.NewScanner(input)
	for sc.Scan() {
		domain, ok := normalizeDomain(sc.Text())
		if !ok {
			continue
		}

		// ignore domains we've seen
		if seen[domain] {
			continue
		}
		seen[domain] = true

		if verbose {
			fmt.Fprintf(os.Stderr, "Sending %s to jobs channel\n", domain)
		}

		// send the job to the channel
		jobs <- Job{domain}
	}

	// check there were no errors reading stdin
	if err := sc.Err(); err != nil {
		return false, err
	}

	return true, nil
}

// normalizeDomain trims an input line, lower-cases it, strips a trailing dot,
// and reduces a URL to its host. Blank lines and comments are skipped.
func normalizeDomain(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		line = u.Hostname()
	}
	line = strings.TrimSuffix(strings.ToLower(line), ".")
	if line == "" {
		return "", false
	}
	return line, true
}
