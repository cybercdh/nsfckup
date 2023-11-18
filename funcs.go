package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	parser "github.com/Cgboal/DomainParser"
	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
)

var extractor parser.Parser

func init() {
	extractor = parser.NewDomainParser()
}

/*
thread-safe way of checking if we've seen domains to check
*/
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

/*
traceIt
takes a domain and performs a dig domain.com +trace
sends NS's to nxs channel
*/
func traceIt(job *Job) {

	if verbose {
		fmt.Printf("dig %s +trace\n", job.domain)
	}

	var dig dnsutil.Dig

	// dig.SetDNS(job.resolver)

	rsps, err := dig.Trace(job.domain)
	if err != nil {
		// there was an issue with the nameserver, probably timing out
		if verbose {
			log.Printf("Tracing %s produced error: %s\n", job.domain, err)
		}
		// dont't return, as we still want to check the problematic nameserver
		// in case it is nxdomain, although tbh likely it wont be.
		// return
	}

	for _, rsp := range rsps {

		/*
		 parse each NS, extract the root domain
		 and send to nxs channel to check
		*/
		for _, ns := range rsp.Msg.Ns {

			// ensure we're handling an NS record
			typ := strings.Split(ns.String(), "\t")[3]

			if strings.Compare(typ, "NS") != 0 {
				continue
			}

			// make a new target
			tgt := Target{domain: job.domain}

			// parse the name server in the msg
			svr := strings.Split(ns.String(), "\t")[4]
			svr = strings.TrimSuffix(svr, ".")
			tgt.ns = svr

			// work with the root domain of the ns
			ns_root_domain := extractor.GetDomain(svr)
			tld := extractor.GetTld(svr)
			ns_domain := ns_root_domain + "." + tld

			// update the target
			tgt.ns_root = ns_domain

			// send tgt to nxs channel
			nxs <- tgt
		}
	}
	return
}

/*
returns true if an NXDOMAIN response is received from dig
*/
func isNX(tgt *Target) (bool, error) {

	if verbose {
		fmt.Printf("dig A %s\n", tgt.ns_root)
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

	// a list of dns resolvers to randomly choose from
	// resolvers := []string{
	// 	"1.1.1.1",
	// 	"1.0.0.1",
	// 	"8.8.8.8",
	// 	"8.8.4.4",
	// 	"9.9.9.9",
	// }

	// seed to randomly select dns server
	// rand.Seed(time.Now().UnixNano())

	seen := make(map[string]bool)

	// read from stdin or from arg
	var input_domains io.Reader
	input_domains = os.Stdin

	arg_domain := flag.Arg(0)
	if arg_domain != "" {
		input_domains = strings.NewReader(arg_domain)
	}

	sc := bufio.NewScanner(input_domains)

	for sc.Scan() {

		// var resolver string

		domain := sc.Text()

		// ignore domains we've seen
		if _, ok := seen[domain]; ok {
			continue
		}

		seen[domain] = true

		// if dnsServer == "" {
		// 	// get a random resolver
		// 	resolver = resolvers[rand.Intn(len(resolvers))]
		// } else {
		// 	// use the one specified by the user
		// 	resolver = dnsServer
		// }

		if verbose {
			fmt.Printf("Sending %s to jobs channel\n", domain)
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
