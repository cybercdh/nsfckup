package main

import "testing"

func TestRegistrable(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"a.gtld-servers.net.", "gtld-servers.net", true},
		{"NS1.Example.CO.UK", "example.co.uk", true},
		{"ns-123.awsdns-45.org", "awsdns-45.org", true},
		{"ns1.dns.example.github.io", "example.github.io", true}, // github.io is a public suffix
		{"com", "", false},
		{"co.uk", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := registrable(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("registrable(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Example.com", "example.com", true},
		{"  example.com.  ", "example.com", true},
		{"https://www.example.com/path", "www.example.com", true},
		{"", "", false},
		{"# comment", "", false},
		{".", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeDomain(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizeDomain(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMarkSeen(t *testing.T) {
	c := Container{seen: make(map[string]bool)}
	if !c.markSeen("a.example") {
		t.Fatal("first markSeen should report new")
	}
	if c.markSeen("a.example") {
		t.Fatal("second markSeen should report already seen")
	}
}
