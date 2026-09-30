## nsfckup
Take a list of domains and inspect their NameServer domains which return an NXDOMAIN response to `dig`. This could indicate a NameServer domain takeover issue, which could be pretty impactful!

## Recommended Usage

`$ cat domains | nsfckup -c 50 -v`

or 

`$ assetfinder example.com | nsfckup -c 50 `

or 

`$ nsfckup example.com`

## Options

```
  -c int
        set the concurrency level (default 20)
  -v    Get more info on attempts (printed to stderr)
```

Output is `domain,nameserver,nameserver_domain,NXDOMAIN`, one line per nameserver domain that returns NXDOMAIN. Input lines may be bare domains or URLs.

## Install

`go install github.com/cybercdh/nsfckup@latest`

## Thanks

A lot of Go concepts were taken from @tomnomnom's excellent repos, particularly [httprobe](https://github.com/tomnomnom/httprobe)

