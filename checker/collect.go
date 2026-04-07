package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Collect probes the delegation and records raw facts only; judgment lives
// in rule.go. Phase B queries delegated servers using only the NS names and
// glue learned from the parent: the child zone is never trusted as a
// source of truth.
func (p *delegationProvider) Collect(ctx context.Context, opts sdk.CheckerOptions) (any, error) {
	svc, err := loadService(opts)
	if err != nil {
		return nil, err
	}

	parentZone, subdomain := loadNames(opts)
	if parentZone == "" {
		return nil, fmt.Errorf("missing 'domain_name' option")
	}

	parent := strings.TrimSuffix(parentZone, ".")
	sub := strings.TrimSuffix(subdomain, ".")
	var delegatedFQDN string
	if sub == "" {
		delegatedFQDN = dns.Fqdn(parent)
	} else {
		delegatedFQDN = dns.Fqdn(sub + "." + parent)
	}

	data := &DelegationData{
		DelegatedFQDN: delegatedFQDN,
		ParentZone:    dns.Fqdn(parentZone),
		DeclaredNS:    normalizeNSList(svc.NameServers),
	}
	for _, d := range svc.DS {
		if d == nil {
			continue
		}
		data.DeclaredDS = append(data.DeclaredDS, NewDSRecord(d))
	}

	_, parentServers, err := findParentZone(ctx, delegatedFQDN, parentZone)
	if err != nil {
		data.ParentDiscoveryError = err.Error()
		return data, nil
	}
	data.ParentNS = parentServers

	// Phase A: per-parent observations, no judgment.
	for _, ps := range parentServers {
		view := ParentView{Server: ps}

		ns, glue, _, qerr := queryDelegation(ctx, ps, delegatedFQDN)
		if qerr != nil {
			view.UDPNSError = qerr.Error()
		} else {
			view.NS = ns
			view.Glue = glue
		}

		if terr := queryDelegationTCP(ctx, ps, delegatedFQDN); terr != nil {
			view.TCPNSError = terr.Error()
		}

		dsRRs, sigs, dserr := queryDS(ctx, ps, delegatedFQDN)
		if dserr != nil {
			view.DSQueryError = dserr.Error()
		} else {
			for _, d := range dsRRs {
				view.DS = append(view.DS, NewDSRecord(d))
			}
			for _, sig := range sigs {
				view.DSRRSIGs = append(view.DSRRSIGs, DSRRSIGObservation{
					Inception:  sig.Inception,
					Expiration: sig.Expiration,
				})
			}
		}

		data.ParentViews = append(data.ParentViews, view)
	}

	// If no parent answered with an NS RRset, skip Phase B; rules flag the gap.
	var primary *ParentView
	for i := range data.ParentViews {
		if data.ParentViews[i].UDPNSError == "" && len(data.ParentViews[i].NS) > 0 {
			primary = &data.ParentViews[i]
			break
		}
	}
	if primary == nil {
		return data, nil
	}

	// Phase B: per-child observations, seeded only from parent data.
	for _, nsName := range primary.NS {
		child := ChildNSView{NSName: nsName}
		addrs := primary.Glue[nsName]
		if len(addrs) == 0 {
			// Out-of-bailiwick: no glue expected, fall back to the system resolver.
			resolved, rerr := resolveHost(ctx, nsName)
			if rerr != nil {
				child.ResolveError = rerr.Error()
				data.Children = append(data.Children, child)
				continue
			}
			addrs = resolved
		}

		for _, addr := range addrs {
			srv := hostPort(addr, "53")
			av := ChildAddressView{Address: addr, Server: srv}

			soa, aa, qerr := querySOA(ctx, "", srv, delegatedFQDN)
			if qerr != nil {
				av.UDPError = qerr.Error()
				av.Authoritative = aa
				child.Addresses = append(child.Addresses, av)
				continue
			}
			av.Authoritative = aa
			if soa != nil {
				av.SOASerial = soa.Serial
				av.SOASerialKnown = true
			}

			if _, _, terr := querySOA(ctx, "tcp", srv, delegatedFQDN); terr != nil {
				av.TCPError = terr.Error()
			}

			childNS, nerr := queryNSAt(ctx, srv, delegatedFQDN)
			if nerr != nil {
				av.ChildNSError = nerr.Error()
			} else {
				av.ChildNS = childNS
			}

			if isInBailiwick(nsName, delegatedFQDN) {
				addrsAt, _ := queryAddrsAt(ctx, srv, nsName)
				av.ChildGlueAddrs = addrsAt
			}

			// DNSKEY is only useful when there's a parent DS to match against.
			parentHasDS := false
			for _, pv := range data.ParentViews {
				if len(pv.DS) > 0 {
					parentHasDS = true
					break
				}
			}
			if parentHasDS {
				keys, kerr := queryDNSKEY(ctx, srv, delegatedFQDN)
				if kerr != nil {
					av.DNSKEYError = kerr.Error()
				} else {
					for _, k := range keys {
						av.DNSKEYs = append(av.DNSKEYs, NewDNSKEYRecord(k))
					}
				}
			}

			child.Addresses = append(child.Addresses, av)
		}

		data.Children = append(data.Children, child)
	}

	return data, nil
}

// queryDelegationTCP only reports reachability; the payload was already
// captured over UDP.
func queryDelegationTCP(ctx context.Context, parentServer, fqdn string) error {
	q := dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	msg, err := dnsExchange(ctx, "tcp", parentServer, q, true)
	if err != nil {
		return err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("parent answered %s", dns.RcodeToString[msg.Rcode])
	}
	return nil
}

// loadService decodes the "service" option into a minimal local type to
// avoid pulling in the full happyDomain server module.
func loadService(opts sdk.CheckerOptions) (*delegationService, error) {
	svc, ok := sdk.GetOption[serviceMessage](opts, "service")
	if !ok {
		return nil, fmt.Errorf("missing 'service' option")
	}
	if svc.Type != "" && svc.Type != "abstract.Delegation" {
		return nil, fmt.Errorf("service is %s, expected abstract.Delegation", svc.Type)
	}
	var d delegationService
	if err := json.Unmarshal(svc.Service, &d); err != nil {
		return nil, fmt.Errorf("decoding delegation service: %w", err)
	}
	return &d, nil
}

func loadNames(opts sdk.CheckerOptions) (parentZone, subdomain string) {
	if v, ok := sdk.GetOption[string](opts, "domain_name"); ok {
		parentZone = v
	}
	if v, ok := sdk.GetOption[string](opts, "subdomain"); ok {
		subdomain = v
	}
	return
}
