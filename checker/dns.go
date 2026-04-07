package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// year68 wraps RRSIG validity periods around 2^32 seconds, matching miekg.
const year68 = int64(1 << 31)

const dnsTimeout = 5 * time.Second

// dnsExchange forces RecursionDesired off: this checker only talks to
// authoritative servers, never recursors.
func dnsExchange(ctx context.Context, proto, server string, q dns.Question, edns bool) (*dns.Msg, error) {
	client := dns.Client{Net: proto, Timeout: dnsTimeout}

	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{q}
	m.RecursionDesired = false
	if edns {
		m.SetEdns0(4096, true)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < client.Timeout {
			client.Timeout = d
		}
	}

	r, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("nil response from %s", server)
	}
	return r, nil
}

// hostPort brackets IPv6 literals so net.Dial accepts them.
func hostPort(host, port string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]:" + port
	}
	host = strings.TrimSuffix(host, ".")
	return host + ":" + port
}

// resolveHost is the fallback path for out-of-bailiwick NS without glue.
func resolveHost(ctx context.Context, host string) ([]string, error) {
	var resolver net.Resolver
	addrs, err := resolver.LookupHost(ctx, strings.TrimSuffix(host, "."))
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// findParentZone returns the parent zone and its authoritative servers.
// hintParent skips the label walk: happyDomain already knows the parent.
func findParentZone(ctx context.Context, fqdn, hintParent string) (zone string, servers []string, err error) {
	zone = dns.Fqdn(hintParent)
	if zone == "" || zone == "." {
		labels := dns.SplitDomainName(fqdn)
		if len(labels) == 0 {
			return "", nil, fmt.Errorf("cannot derive parent of %q", fqdn)
		}
		zone = dns.Fqdn(strings.Join(labels[1:], "."))
	}

	servers, err = resolveZoneNSAddrs(ctx, zone)
	if err != nil {
		return "", nil, fmt.Errorf("resolving NS of parent zone %q: %w", zone, err)
	}
	if len(servers) == 0 {
		return "", nil, fmt.Errorf("parent zone %q has no resolvable NS", zone)
	}
	return zone, servers, nil
}

// resolveZoneNSAddrs returns "host:53" entries for the zone's NS set.
func resolveZoneNSAddrs(ctx context.Context, zone string) ([]string, error) {
	var resolver net.Resolver
	nss, err := resolver.LookupNS(ctx, strings.TrimSuffix(zone, "."))
	if err != nil {
		return nil, err
	}

	var out []string
	for _, ns := range nss {
		addrs, err := resolver.LookupHost(ctx, strings.TrimSuffix(ns.Host, "."))
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			out = append(out, hostPort(a, "53"))
		}
	}
	return out, nil
}

// queryDelegation expects a referral response (no RD) and pulls NS + glue
// from every section so misconfigured parents (NS in Answer) still parse.
func queryDelegation(ctx context.Context, parentServer, fqdn string) (ns []string, glue map[string][]string, msg *dns.Msg, err error) {
	q := dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeNS, Qclass: dns.ClassINET}

	msg, err = dnsExchange(ctx, "", parentServer, q, true)
	if err != nil {
		return nil, nil, nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, nil, msg, fmt.Errorf("parent answered %s", dns.RcodeToString[msg.Rcode])
	}

	glue = map[string][]string{}

	collect := func(records []dns.RR) {
		for _, rr := range records {
			switch t := rr.(type) {
			case *dns.NS:
				if strings.EqualFold(strings.TrimSuffix(t.Header().Name, "."), strings.TrimSuffix(fqdn, ".")) {
					ns = append(ns, strings.ToLower(dns.Fqdn(t.Ns)))
				}
			case *dns.A:
				name := strings.ToLower(dns.Fqdn(t.Header().Name))
				glue[name] = append(glue[name], t.A.String())
			case *dns.AAAA:
				name := strings.ToLower(dns.Fqdn(t.Header().Name))
				glue[name] = append(glue[name], t.AAAA.String())
			}
		}
	}
	collect(msg.Answer)
	collect(msg.Ns)
	collect(msg.Extra)
	return
}

// queryDS uses TCP because DS+RRSIG answers commonly exceed UDP MTU.
func queryDS(ctx context.Context, parentServer, fqdn string) (ds []*dns.DS, sigs []*dns.RRSIG, err error) {
	q := dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeDS, Qclass: dns.ClassINET}

	r, err := dnsExchange(ctx, "tcp", parentServer, q, true)
	if err != nil {
		return nil, nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("parent answered %s for DS", dns.RcodeToString[r.Rcode])
	}

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.DS:
			ds = append(ds, t)
		case *dns.RRSIG:
			sigs = append(sigs, t)
		}
	}
	return
}

// querySOA also returns the AA flag so callers can detect lame servers.
func querySOA(ctx context.Context, proto, server, fqdn string) (soa *dns.SOA, aa bool, err error) {
	q := dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeSOA, Qclass: dns.ClassINET}
	r, err := dnsExchange(ctx, proto, server, q, false)
	if err != nil {
		return nil, false, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, r.Authoritative, fmt.Errorf("server answered %s", dns.RcodeToString[r.Rcode])
	}
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.SOA); ok {
			return t, r.Authoritative, nil
		}
	}
	return nil, r.Authoritative, fmt.Errorf("no SOA in answer section")
}

func queryNSAt(ctx context.Context, server, fqdn string) ([]string, error) {
	q := dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	r, err := dnsExchange(ctx, "", server, q, false)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("server answered %s", dns.RcodeToString[r.Rcode])
	}
	var out []string
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.NS); ok {
			out = append(out, strings.ToLower(dns.Fqdn(t.Ns)))
		}
	}
	return out, nil
}

func queryAddrsAt(ctx context.Context, server, host string) ([]string, error) {
	var out []string
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r, err := dnsExchange(ctx, "", server, dns.Question{Name: dns.Fqdn(host), Qtype: qt, Qclass: dns.ClassINET}, false)
		if err != nil {
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range r.Answer {
			switch t := rr.(type) {
			case *dns.A:
				out = append(out, t.A.String())
			case *dns.AAAA:
				out = append(out, t.AAAA.String())
			}
		}
	}
	return out, nil
}

func queryDNSKEY(ctx context.Context, server, fqdn string) ([]*dns.DNSKEY, error) {
	q := dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	r, err := dnsExchange(ctx, "tcp", server, q, true)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("server answered %s for DNSKEY", dns.RcodeToString[r.Rcode])
	}
	var out []*dns.DNSKEY
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, t)
		}
	}
	return out, nil
}

func dsEqual(a, b *dns.DS) bool {
	return a.KeyTag == b.KeyTag &&
		a.Algorithm == b.Algorithm &&
		a.DigestType == b.DigestType &&
		strings.EqualFold(a.Digest, b.Digest)
}
