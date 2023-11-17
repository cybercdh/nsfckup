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
  -d string
        specify a custom DNS resolver address
  -s    Be strict on CNAME, must include the target domain
  -v    Get more info on attempts
```

## Install

You need to have the latest version (1.19+) of [Go installed](https://golang.org/doc/install) and configured (i.e. with $GOPATH/bin in your $PATH):

`go get -u github.com/cybercdh/nsfckup`

or

`go install github.com/cybercdh/nsfckup@latest`


## Thanks

A lot of Go concepts were taken from @tomnomnom's excellent repos, particularly [httprobe](https://github.com/tomnomnom/httprobe)

