package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
	"io"
	"os"
	"strings"

	parser "github.com/Cgboal/DomainParser"
)

var extractor parser.Parser

func init() {
	extractor = parser.NewDomainParser()
}

/*
traceIt
takes a domain and performs a dig domain.com +trace
sends NS's to nxs channel
*/
func traceIt(domainToTrace string) {

	if verbose {
		fmt.Printf("Tracing %s\n", domainToTrace)
	}

	var dig dnsutil.Dig
	rsps, err := dig.Trace(domainToTrace)
	if err != nil {
		return
	}
	for _, rsp := range rsps {

		// check if we have a CNAME and recurse
		ans := rsp.Msg.Answer
		if len(ans) > 0 {
			ans_type := strings.Split(ans[0].String(), "\t")[3]
			if strings.Contains(ans_type, "CNAME") {
				cname_domain := strings.Split(ans[0].String(), "\t")[4]
				cname_domain = strings.TrimSuffix(cname_domain, ".")

				if verbose {
					fmt.Printf("Found CNAME: %s\n", cname_domain)
				}

				if strict {
					if !strings.Contains(cname_domain, domainToTrace) {
						return
					}
				}

				traceIt(cname_domain)

				return
			}
		}

		// parse each NS, extract the root domain and send to nxs channel to check
		for _, ns := range rsp.Msg.Ns {
			svr := strings.Split(ns.String(), "\t")[4]
			typ := strings.Split(ns.String(), "\t")[3]

			if !strings.Contains(typ, "NS") {
				continue
			}

			if verbose {
				fmt.Printf("Found NS: %s\n", svr)
			}

			dom := extractor.GetDomain(svr)
			tld := extractor.GetTld(svr)
			domain := dom + "." + tld

			// send nameserver to nxs channel
			nxs <- domain
		}
	}
	return
}

/*
returns true if an NXDOMAIN response is received from dig
*/
func isNX(domain string) (bool, error) {

	if verbose {
		fmt.Printf("Performing dig A %s\n", domain)
	}
	var dig dnsutil.Dig
	dig.Retry = 3

	msg, err := dig.GetMsg(dns.TypeA, domain)
	if err != nil {
		return false, err
	}
	if strings.Contains(msg.String(), "NXDOMAIN") {
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
	var input_domains io.Reader
	input_domains = os.Stdin

	arg_domain := flag.Arg(0)
	if arg_domain != "" {
		input_domains = strings.NewReader(arg_domain)
	}

	sc := bufio.NewScanner(input_domains)

	for sc.Scan() {

		domain := sc.Text()

		// ignore domains we've seen
		if _, ok := seen[domain]; ok {
			continue
		}

		seen[domain] = true

		domains <- domain

	}

	// check there were no errors reading stdin
	if err := sc.Err(); err != nil {
		return false, err
	}

	return true, nil
}
