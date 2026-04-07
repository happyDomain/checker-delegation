package checker

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// GetHTMLReport falls back to a data-only render when the host hasn't
// threaded rule states into the context yet.
func (p *delegationProvider) GetHTMLReport(ctx sdk.ReportContext) (string, error) {
	var data DelegationData
	if raw := ctx.Data(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			return "", fmt.Errorf("decoding delegation data: %w", err)
		}
	}

	states := ctx.States()

	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<title>Delegation report</title></head><body style="font-family:sans-serif">`)

	fmt.Fprintf(&b, `<h1>Delegation of %s</h1>`, html.EscapeString(strings.TrimSuffix(data.DelegatedFQDN, ".")))

	if len(states) == 0 {
		b.WriteString(`<p><em>No rule states were threaded into this report; rendering raw observation only.</em></p>`)
		writeDataOnly(&b, &data)
		b.WriteString(`</body></html>`)
		return b.String(), nil
	}

	writeBanner(&b, states)
	writeFixTheseFirst(&b, states)
	writeAllStates(&b, states)
	writeDataOnly(&b, &data)

	b.WriteString(`</body></html>`)
	return b.String(), nil
}

func (p *delegationProvider) ExtractMetrics(ctx sdk.ReportContext, collectedAt time.Time) ([]sdk.CheckMetric, error) {
	var data DelegationData
	if raw := ctx.Data(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("decoding delegation data: %w", err)
		}
	}

	var metrics []sdk.CheckMetric

	metrics = append(metrics, sdk.CheckMetric{
		Name:      "delegation.parent_views.count",
		Value:     float64(len(data.ParentViews)),
		Timestamp: collectedAt,
	})
	metrics = append(metrics, sdk.CheckMetric{
		Name:      "delegation.child_servers.count",
		Value:     float64(len(data.Children)),
		Timestamp: collectedAt,
	})

	byRuleStatus := map[string]map[sdk.Status]int{}
	byStatus := map[sdk.Status]int{}
	for _, s := range ctx.States() {
		byStatus[s.Status]++
		if byRuleStatus[s.RuleName] == nil {
			byRuleStatus[s.RuleName] = map[sdk.Status]int{}
		}
		byRuleStatus[s.RuleName][s.Status]++
	}

	for rule, perStatus := range byRuleStatus {
		for status, n := range perStatus {
			metrics = append(metrics, sdk.CheckMetric{
				Name:  "delegation.rule.status",
				Value: float64(n),
				Labels: map[string]string{
					"rule":   rule,
					"status": status.String(),
				},
				Timestamp: collectedAt,
			})
		}
	}

	for status, n := range byStatus {
		if status == sdk.StatusOK {
			continue
		}
		metrics = append(metrics, sdk.CheckMetric{
			Name:      "delegation.findings.count",
			Value:     float64(n),
			Labels:    map[string]string{"status": status.String()},
			Timestamp: collectedAt,
		})
	}

	return metrics, nil
}

func worstStatus(states []sdk.CheckState) sdk.Status {
	worst := sdk.StatusOK
	for _, s := range states {
		if s.Status > worst {
			worst = s.Status
		}
	}
	return worst
}

func statusColor(s sdk.Status) string {
	switch s {
	case sdk.StatusOK:
		return "#2e7d32"
	case sdk.StatusInfo:
		return "#0277bd"
	case sdk.StatusWarn:
		return "#ef6c00"
	case sdk.StatusCrit:
		return "#c62828"
	case sdk.StatusError:
		return "#6a1b9a"
	default:
		return "#555"
	}
}

func writeBanner(b *strings.Builder, states []sdk.CheckState) {
	worst := worstStatus(states)
	fmt.Fprintf(b, `<p style="padding:.5em 1em;background:%s;color:#fff;display:inline-block;border-radius:4px">Overall: <strong>%s</strong></p>`,
		statusColor(worst), worst.String())
}

func writeFixTheseFirst(b *strings.Builder, states []sdk.CheckState) {
	var fix []sdk.CheckState
	for _, s := range states {
		if s.Status >= sdk.StatusWarn {
			fix = append(fix, s)
		}
	}
	if len(fix) == 0 {
		return
	}
	sort.SliceStable(fix, func(i, j int) bool {
		if fix[i].Status != fix[j].Status {
			return fix[i].Status > fix[j].Status
		}
		if fix[i].RuleName != fix[j].RuleName {
			return fix[i].RuleName < fix[j].RuleName
		}
		return fix[i].Subject < fix[j].Subject
	})
	b.WriteString(`<h2>Fix these first</h2>`)
	writeStatesTable(b, fix)
}

func writeAllStates(b *strings.Builder, states []sdk.CheckState) {
	sorted := append([]sdk.CheckState(nil), states...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RuleName != sorted[j].RuleName {
			return sorted[i].RuleName < sorted[j].RuleName
		}
		return sorted[i].Subject < sorted[j].Subject
	})
	b.WriteString(`<h2>All rule states</h2>`)
	writeStatesTable(b, sorted)
}

func writeStatesTable(b *strings.Builder, states []sdk.CheckState) {
	b.WriteString(`<table style="border-collapse:collapse" cellpadding="4" border="1">`)
	b.WriteString(`<thead><tr><th>Status</th><th>Rule</th><th>Subject</th><th>Message</th></tr></thead><tbody>`)
	for _, s := range states {
		fmt.Fprintf(b, `<tr><td style="color:%s;font-weight:bold">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			statusColor(s.Status),
			html.EscapeString(s.Status.String()),
			html.EscapeString(s.RuleName),
			html.EscapeString(s.Subject),
			html.EscapeString(s.Message),
		)
	}
	b.WriteString(`</tbody></table>`)
}

func writeDataOnly(b *strings.Builder, data *DelegationData) {
	b.WriteString(`<h2>Observation</h2>`)
	if data.ParentDiscoveryError != "" {
		fmt.Fprintf(b, `<p><strong>Parent discovery error:</strong> %s</p>`, html.EscapeString(data.ParentDiscoveryError))
	}

	if len(data.DeclaredNS) > 0 {
		fmt.Fprintf(b, `<p><strong>Declared NS:</strong> %s</p>`, html.EscapeString(strings.Join(data.DeclaredNS, ", ")))
	}
	if len(data.DeclaredDS) > 0 {
		var texts []string
		for _, d := range data.DeclaredDS {
			texts = append(texts, fmt.Sprintf("keytag=%d algo=%d digest-type=%d", d.KeyTag, d.Algorithm, d.DigestType))
		}
		fmt.Fprintf(b, `<p><strong>Declared DS:</strong> %s</p>`, html.EscapeString(strings.Join(texts, "; ")))
	}

	if len(data.ParentViews) > 0 {
		b.WriteString(`<h3>Parent views</h3><ul>`)
		for _, v := range data.ParentViews {
			fmt.Fprintf(b, `<li><strong>%s</strong>: NS=[%s], glue=%d, DS=%d`,
				html.EscapeString(v.Server),
				html.EscapeString(strings.Join(v.NS, ", ")),
				len(v.Glue), len(v.DS))
			if v.UDPNSError != "" {
				fmt.Fprintf(b, `, UDP err=%s`, html.EscapeString(v.UDPNSError))
			}
			if v.TCPNSError != "" {
				fmt.Fprintf(b, `, TCP err=%s`, html.EscapeString(v.TCPNSError))
			}
			if v.DSQueryError != "" {
				fmt.Fprintf(b, `, DS err=%s`, html.EscapeString(v.DSQueryError))
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}

	if len(data.Children) > 0 {
		b.WriteString(`<h3>Delegated servers</h3><ul>`)
		for _, c := range data.Children {
			fmt.Fprintf(b, `<li><strong>%s</strong>`, html.EscapeString(c.NSName))
			if c.ResolveError != "" {
				fmt.Fprintf(b, ` (resolve err: %s)`, html.EscapeString(c.ResolveError))
			}
			if len(c.Addresses) > 0 {
				b.WriteString(`<ul>`)
				for _, a := range c.Addresses {
					fmt.Fprintf(b, `<li>%s, AA=%t`, html.EscapeString(a.Address), a.Authoritative)
					if a.SOASerialKnown {
						fmt.Fprintf(b, `, SOA=%d`, a.SOASerial)
					}
					if a.UDPError != "" {
						fmt.Fprintf(b, `, UDP err=%s`, html.EscapeString(a.UDPError))
					}
					if a.TCPError != "" {
						fmt.Fprintf(b, `, TCP err=%s`, html.EscapeString(a.TCPError))
					}
					if a.DNSKEYError != "" {
						fmt.Fprintf(b, `, DNSKEY err=%s`, html.EscapeString(a.DNSKEYError))
					} else if len(a.DNSKEYs) > 0 {
						fmt.Fprintf(b, `, DNSKEYs=%d`, len(a.DNSKEYs))
					}
					b.WriteString(`</li>`)
				}
				b.WriteString(`</ul>`)
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}
}
