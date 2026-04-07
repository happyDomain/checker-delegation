package checker

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func TestDiffStringSets(t *testing.T) {
	cases := []struct {
		name           string
		want, got      []string
		missing, extra []string
	}{
		{
			name:    "identical",
			want:    []string{"a.example.", "b.example."},
			got:     []string{"a.example.", "b.example."},
			missing: nil, extra: nil,
		},
		{
			name:    "case and trailing dot are normalized",
			want:    []string{"A.Example."},
			got:     []string{"a.example"},
			missing: nil, extra: nil,
		},
		{
			name:    "missing and extra reported",
			want:    []string{"a.example.", "b.example."},
			got:     []string{"b.example.", "c.example."},
			missing: []string{"a.example"},
			extra:   []string{"c.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMissing, gotExtra := diffStringSets(tc.want, tc.got)
			if !reflect.DeepEqual(gotMissing, tc.missing) {
				t.Errorf("missing: got %v want %v", gotMissing, tc.missing)
			}
			if !reflect.DeepEqual(gotExtra, tc.extra) {
				t.Errorf("extra: got %v want %v", gotExtra, tc.extra)
			}
		})
	}
}

func TestIsInBailiwick(t *testing.T) {
	cases := []struct {
		host, zone string
		want       bool
	}{
		{"ns1.example.com.", "example.com.", true},
		{"ns1.example.com", "example.com", true},
		{"example.com.", "example.com.", true},
		{"ns1.other.com.", "example.com.", false},
		{"ns1.notexample.com.", "example.com.", false}, // suffix-but-not-subdomain trap
		{"NS1.Example.COM", "example.com", true},
	}
	for _, tc := range cases {
		if got := isInBailiwick(tc.host, tc.zone); got != tc.want {
			t.Errorf("isInBailiwick(%q,%q)=%v want %v", tc.host, tc.zone, got, tc.want)
		}
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{"192.0.2.1", "53", "192.0.2.1:53"},
		{"2001:db8::1", "53", "[2001:db8::1]:53"},
		{"ns1.example.com.", "53", "ns1.example.com:53"},
	}
	for _, tc := range cases {
		if got := hostPort(tc.host, tc.port); got != tc.want {
			t.Errorf("hostPort(%q,%q)=%q want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestNormalizeNSList(t *testing.T) {
	in := []*dns.NS{
		{Ns: "B.example.COM"},
		nil, // must be skipped
		{Ns: "a.example.com."},
	}
	want := []string{"a.example.com.", "b.example.com."}
	got := normalizeNSList(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeNSList: got %v want %v", got, want)
	}
}

func TestDiffDS(t *testing.T) {
	a := &dns.DS{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "AAAA"}
	b := &dns.DS{KeyTag: 2, Algorithm: 8, DigestType: 2, Digest: "BBBB"}
	c := &dns.DS{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "aaaa"} // case-insensitive digest

	missing, extra := diffDS([]*dns.DS{a, b}, []*dns.DS{c})
	if len(missing) != 1 || missing[0] != b {
		t.Errorf("missing: got %v want [b]", missing)
	}
	if len(extra) != 0 {
		t.Errorf("extra: got %v want []", extra)
	}
}

func TestDSMatchesAnyKey(t *testing.T) {
	// Build a DNSKEY and derive its DS, so we know they match.
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		// A throwaway public key; ToDS only needs the wire form to be deterministic.
		PublicKey: "AwEAAcMnWBKLuvG/LwnPVykcmpvnntwxfshHlHRhlY0F3oz8AMcuF8gw" +
			"2Ge56vG9oqVxTzHl4Ss2dEqCQOjFlOVo+pa3JwIO1lUzbQ==",
	}
	matchingDS := key.ToDS(dns.SHA256)
	if matchingDS == nil {
		t.Fatal("could not derive DS from DNSKEY")
	}
	other := &dns.DS{KeyTag: 9999, Algorithm: 99, DigestType: 99, Digest: "DEAD"}

	if !dsMatchesAnyKey([]*dns.DS{matchingDS, other}, []*dns.DNSKEY{key}) {
		t.Error("expected match between key and its derived DS")
	}
	if dsMatchesAnyKey([]*dns.DS{other}, []*dns.DNSKEY{key}) {
		t.Error("unexpected match against unrelated DS")
	}
	if dsMatchesAnyKey(nil, []*dns.DNSKEY{key}) {
		t.Error("no DS records: must not match")
	}
}
