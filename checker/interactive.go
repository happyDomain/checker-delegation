//go:build standalone

package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

func (p *delegationProvider) RenderForm() []sdk.CheckerOptionField {
	return []sdk.CheckerOptionField{
		{
			Id:          "domain",
			Type:        "string",
			Label:       "Delegated domain",
			Placeholder: "sub.example.com",
			Required:    true,
			Description: "Fully-qualified name of the delegated zone to check.",
		},
	}
}

func (p *delegationProvider) ParseForm(r *http.Request) (sdk.CheckerOptions, error) {
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	fqdn := dns.Fqdn(domain)
	labels := dns.SplitDomainName(fqdn)
	if len(labels) < 2 {
		return nil, fmt.Errorf("%q has no parent zone", domain)
	}
	parentZone := strings.Join(labels[1:], ".")
	subdomain := labels[0]

	resolver := interactiveResolver()

	ctx := r.Context()
	var (
		wg        sync.WaitGroup
		nsRecords []*dns.NS
		dsRecords []*dns.DS
		nsErr     error
		dsErr     error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		nsRecords, nsErr = lookupRecords[*dns.NS](ctx, resolver, fqdn, dns.TypeNS, false)
	}()
	go func() {
		defer wg.Done()
		dsRecords, dsErr = lookupRecords[*dns.DS](ctx, resolver, fqdn, dns.TypeDS, true)
	}()
	wg.Wait()

	if nsErr != nil {
		return nil, fmt.Errorf("NS lookup for %s: %w", domain, nsErr)
	}
	if len(nsRecords) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", domain)
	}
	if dsErr != nil {
		return nil, fmt.Errorf("DS lookup for %s: %w", domain, dsErr)
	}

	body, err := json.Marshal(delegationService{NameServers: nsRecords, DS: dsRecords})
	if err != nil {
		return nil, fmt.Errorf("marshal delegation service: %w", err)
	}

	svc := serviceMessage{
		Type:    "abstract.Delegation",
		Service: body,
	}

	return sdk.CheckerOptions{
		"domain_name": parentZone,
		"subdomain":   subdomain,
		"service":     svc,
	}, nil
}

var (
	resolverOnce sync.Once
	resolverAddr string

	interactiveClient = &dns.Client{Timeout: dnsTimeout}
)

func interactiveResolver() string {
	resolverOnce.Do(func() {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cfg.Servers) == 0 {
			resolverAddr = net.JoinHostPort("1.1.1.1", "53")
			return
		}
		resolverAddr = net.JoinHostPort(cfg.Servers[0], cfg.Port)
	})
	return resolverAddr
}

func lookupRecords[T dns.RR](ctx context.Context, resolver, fqdn string, qtype uint16, edns bool) ([]T, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true
	if edns {
		msg.SetEdns0(4096, true)
	}

	in, _, err := interactiveClient.ExchangeContext(ctx, msg, resolver)
	if err != nil {
		return nil, err
	}
	if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[in.Rcode])
	}

	var out []T
	for _, rr := range in.Answer {
		if t, ok := rr.(T); ok {
			out = append(out, t)
		}
	}
	return out, nil
}
