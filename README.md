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

-s  be strict with recursively checking CNAMES

-v  get more info on URL attempts
```

## Install

You need to have [Go installed](https://golang.org/doc/install) and configured (i.e. with $GOPATH/bin in your $PATH):

`go get -u github.com/cybercdh/nsfckup`

or

`go install github.com/cybercdh/nsfckup@latest`


## Thanks

A lot of Go concepts were taken from @tomnomnom's excellent repos, particularly [httprobe](https://github.com/tomnomnom/httprobe)

