package checker

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

func normalizeNSList(ns []*dns.NS) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		if n == nil {
			continue
		}
		out = append(out, strings.ToLower(dns.Fqdn(n.Ns)))
	}
	sort.Strings(out)
	return out
}

func diffStringSets(want, got []string) (missing, extra []string) {
	w := map[string]bool{}
	for _, v := range want {
		w[strings.ToLower(strings.TrimSuffix(v, "."))] = true
	}
	g := map[string]bool{}
	for _, v := range got {
		g[strings.ToLower(strings.TrimSuffix(v, "."))] = true
	}
	for k := range w {
		if !g[k] {
			missing = append(missing, k)
		}
	}
	for k := range g {
		if !w[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

func diffDS(want, got []*dns.DS) (missing, extra []*dns.DS) {
	for _, w := range want {
		found := false
		for _, g := range got {
			if dsEqual(w, g) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		found := false
		for _, w := range want {
			if dsEqual(w, g) {
				found = true
				break
			}
		}
		if !found {
			extra = append(extra, g)
		}
	}
	return
}

func isInBailiwick(host, zone string) bool {
	host = strings.ToLower(dns.Fqdn(host))
	zone = strings.ToLower(dns.Fqdn(zone))
	return host == zone || strings.HasSuffix(host, "."+zone)
}

func dsMatchesAnyKey(ds []*dns.DS, keys []*dns.DNSKEY) bool {
	for _, k := range keys {
		for _, d := range ds {
			expected := k.ToDS(d.DigestType)
			if expected != nil && dsEqual(expected, d) {
				return true
			}
		}
	}
	return false
}

// dsRecordsToMiekg lets diff/matcher helpers stay miekg-typed.
func dsRecordsToMiekg(list []DSRecord) []*dns.DS {
	out := make([]*dns.DS, 0, len(list))
	for _, d := range list {
		out = append(out, d.ToMiekg())
	}
	return out
}

// dnskeysToMiekg restores miekg form so k.ToDS is callable.
func dnskeysToMiekg(list []DNSKEYRecord) []*dns.DNSKEY {
	out := make([]*dns.DNSKEY, 0, len(list))
	for _, k := range list {
		out = append(out, k.ToMiekg())
	}
	return out
}
