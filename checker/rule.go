package checker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Rules returns the full rule set. All rules share one DelegationData
// observation and emit one CheckState per evaluated subject.
func Rules() []sdk.CheckRule {
	return []sdk.CheckRule{
		&minNameServersRule{},
		&parentDiscoveredRule{},
		&parentNSQueryRule{},
		&parentTCPRule{},
		&nsMatchesDeclaredRule{},
		&inBailiwickGlueRule{},
		&unnecessaryGlueRule{},
		&dsQueryRule{},
		&dsMatchesDeclaredRule{},
		&dsPresentAtParentRule{},
		&dsRRSIGValidityRule{},
		&nsResolvableRule{},
		&childReachableRule{},
		&childAuthoritativeRule{},
		&childSOASerialDriftRule{},
		&childTCPRule{},
		&childNSMatchesParentRule{},
		&childGlueMatchesParentRule{},
		&dnskeyQueryRule{},
		&dnskeyMatchesDSRule{},
		&nsHasAuthoritativeAnswerRule{},
	}
}

func loadData(ctx context.Context, obs sdk.ObservationGetter, code string) (*DelegationData, []sdk.CheckState) {
	var data DelegationData
	if err := obs.Get(ctx, ObservationKeyDelegation, &data); err != nil {
		return nil, []sdk.CheckState{{
			Status:  sdk.StatusError,
			Message: fmt.Sprintf("Failed to get delegation data: %v", err),
			Code:    code,
		}}
	}
	return &data, nil
}

// primaryParentView mirrors Collect's Phase-B source-of-truth choice.
func primaryParentView(views []ParentView) *ParentView {
	for i := range views {
		if views[i].UDPNSError == "" && len(views[i].NS) > 0 {
			return &views[i]
		}
	}
	return nil
}

// ───────────────────────── checker-wide rules ─────────────────────────

type minNameServersRule struct{}

func (r *minNameServersRule) Name() string { return "delegation_min_name_servers" }
func (r *minNameServersRule) Description() string {
	return "Checks that enough name servers are declared for the delegation (RFC 1034 recommends at least 2)"
}
func (r *minNameServersRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_too_few_ns")
	if errState != nil {
		return errState
	}
	minNS := sdk.GetIntOption(opts, "minNameServers", 2)
	if len(data.DeclaredNS) < minNS {
		return []sdk.CheckState{{
			Status:  sdk.StatusWarn,
			Code:    "delegation_too_few_ns",
			Message: fmt.Sprintf("only %d name server(s) declared, at least %d recommended", len(data.DeclaredNS), minNS),
			Meta:    map[string]any{"declared": len(data.DeclaredNS), "minimum": minNS},
		}}
	}
	return []sdk.CheckState{{
		Status:  sdk.StatusOK,
		Code:    "delegation_too_few_ns",
		Message: fmt.Sprintf("%d name server(s) declared", len(data.DeclaredNS)),
	}}
}

type parentDiscoveredRule struct{}

func (r *parentDiscoveredRule) Name() string { return "delegation_parent_discovered" }
func (r *parentDiscoveredRule) Description() string {
	return "Verifies that the parent zone's authoritative servers could be discovered"
}
func (r *parentDiscoveredRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_no_parent_ns")
	if errState != nil {
		return errState
	}
	if data.ParentDiscoveryError != "" {
		return []sdk.CheckState{{
			Status:  sdk.StatusCrit,
			Code:    "delegation_no_parent_ns",
			Message: data.ParentDiscoveryError,
		}}
	}
	if len(data.ParentNS) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusCrit,
			Code:    "delegation_no_parent_ns",
			Message: "parent zone has no resolvable authoritative servers",
		}}
	}
	return []sdk.CheckState{{
		Status:  sdk.StatusOK,
		Code:    "delegation_no_parent_ns",
		Message: fmt.Sprintf("%d parent authoritative server(s) discovered", len(data.ParentNS)),
	}}
}

// ───────────────────────── parent-side rules ─────────────────────────

type parentNSQueryRule struct{}

func (r *parentNSQueryRule) Name() string { return "delegation_parent_ns_query" }
func (r *parentNSQueryRule) Description() string {
	return "Verifies that every parent authoritative server answers the NS query for the delegated FQDN"
}
func (r *parentNSQueryRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_parent_query_failed")
	if errState != nil {
		return errState
	}
	if len(data.ParentViews) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_parent_query_failed",
			Message: "no parent server was queried",
		}}
	}
	out := make([]sdk.CheckState, 0, len(data.ParentViews))
	for _, v := range data.ParentViews {
		st := sdk.CheckState{Code: "delegation_parent_query_failed", Subject: v.Server}
		switch {
		case v.UDPNSError != "":
			st.Status = sdk.StatusCrit
			st.Message = fmt.Sprintf("parent NS query failed: %s", v.UDPNSError)
		case len(v.NS) == 0:
			st.Status = sdk.StatusCrit
			st.Message = "parent returned an empty NS RRset"
		default:
			st.Status = sdk.StatusOK
			st.Message = fmt.Sprintf("%d NS record(s) returned", len(v.NS))
		}
		out = append(out, st)
	}
	return out
}

type parentTCPRule struct{}

func (r *parentTCPRule) Name() string { return "delegation_parent_tcp" }
func (r *parentTCPRule) Description() string {
	return "Verifies that every parent authoritative server answers the NS query over TCP"
}
func (r *parentTCPRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_parent_tcp_failed")
	if errState != nil {
		return errState
	}
	if len(data.ParentViews) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_parent_tcp_failed",
			Message: "no parent server was queried",
		}}
	}
	requireTCP := sdk.GetBoolOption(opts, "requireTCP", true)
	failStatus := sdk.StatusCrit
	if !requireTCP {
		failStatus = sdk.StatusWarn
	}
	out := make([]sdk.CheckState, 0, len(data.ParentViews))
	for _, v := range data.ParentViews {
		st := sdk.CheckState{Code: "delegation_parent_tcp_failed", Subject: v.Server}
		if v.TCPNSError != "" {
			st.Status = failStatus
			st.Message = fmt.Sprintf("parent NS query over TCP failed: %s", v.TCPNSError)
		} else {
			st.Status = sdk.StatusOK
			st.Message = "TCP reachable"
		}
		out = append(out, st)
	}
	return out
}

type nsMatchesDeclaredRule struct{}

func (r *nsMatchesDeclaredRule) Name() string { return "delegation_ns_matches_declared" }
func (r *nsMatchesDeclaredRule) Description() string {
	return "Verifies that the NS RRset served by the parent matches the service's declared name servers"
}
func (r *nsMatchesDeclaredRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ns_mismatch")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, v := range data.ParentViews {
		if v.UDPNSError != "" || len(v.NS) == 0 {
			continue
		}
		missing, extra := diffStringSets(data.DeclaredNS, v.NS)
		st := sdk.CheckState{Code: "delegation_ns_mismatch", Subject: v.Server}
		if len(missing) > 0 || len(extra) > 0 {
			st.Status = sdk.StatusCrit
			st.Message = fmt.Sprintf("NS RRset does not match declared: missing=%v extra=%v", missing, extra)
			st.Meta = map[string]any{"missing": missing, "extra": extra}
		} else {
			st.Status = sdk.StatusOK
			st.Message = "NS RRset matches the declared service"
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_ns_mismatch",
			Message: "no parent server returned an NS RRset",
		}}
	}
	return out
}

type inBailiwickGlueRule struct{}

func (r *inBailiwickGlueRule) Name() string { return "delegation_in_bailiwick_glue" }
func (r *inBailiwickGlueRule) Description() string {
	return "Verifies that every in-bailiwick NS hostname has glue records at the parent"
}
func (r *inBailiwickGlueRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_missing_glue")
	if errState != nil {
		return errState
	}
	if len(data.ParentViews) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_missing_glue",
			Message: "no parent server was queried",
		}}
	}
	var out []sdk.CheckState
	for _, v := range data.ParentViews {
		if v.UDPNSError != "" {
			continue
		}
		for _, n := range v.NS {
			if !isInBailiwick(n, data.DelegatedFQDN) {
				continue
			}
			subject := fmt.Sprintf("%s@%s", n, v.Server)
			if len(v.Glue[n]) == 0 {
				out = append(out, sdk.CheckState{
					Status:  sdk.StatusCrit,
					Code:    "delegation_missing_glue",
					Subject: subject,
					Message: "in-bailiwick NS has no glue",
				})
			} else {
				out = append(out, sdk.CheckState{
					Status:  sdk.StatusOK,
					Code:    "delegation_missing_glue",
					Subject: subject,
					Message: fmt.Sprintf("%d glue address(es)", len(v.Glue[n])),
				})
			}
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusOK,
			Code:    "delegation_missing_glue",
			Message: "no in-bailiwick NS, glue not required",
		}}
	}
	return out
}

type unnecessaryGlueRule struct{}

func (r *unnecessaryGlueRule) Name() string { return "delegation_unnecessary_glue" }
func (r *unnecessaryGlueRule) Description() string {
	return "Flags out-of-bailiwick NS hostnames for which the parent still returns glue"
}
func (r *unnecessaryGlueRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_unnecessary_glue")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, v := range data.ParentViews {
		if v.UDPNSError != "" {
			continue
		}
		for _, n := range v.NS {
			if isInBailiwick(n, data.DelegatedFQDN) {
				continue
			}
			subject := fmt.Sprintf("%s@%s", n, v.Server)
			if len(v.Glue[n]) > 0 {
				out = append(out, sdk.CheckState{
					Status:  sdk.StatusWarn,
					Code:    "delegation_unnecessary_glue",
					Subject: subject,
					Message: "out-of-bailiwick NS has glue records at the parent",
				})
			} else {
				out = append(out, sdk.CheckState{
					Status:  sdk.StatusOK,
					Code:    "delegation_unnecessary_glue",
					Subject: subject,
					Message: "no glue (expected)",
				})
			}
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusInfo,
			Code:    "delegation_unnecessary_glue",
			Message: "no out-of-bailiwick NS to evaluate",
		}}
	}
	return out
}

type dsQueryRule struct{}

func (r *dsQueryRule) Name() string { return "delegation_ds_query" }
func (r *dsQueryRule) Description() string {
	return "Verifies that every parent authoritative server answers the DS query for the delegated FQDN"
}
func (r *dsQueryRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ds_query_failed")
	if errState != nil {
		return errState
	}
	if len(data.ParentViews) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_ds_query_failed",
			Message: "no parent server was queried",
		}}
	}
	out := make([]sdk.CheckState, 0, len(data.ParentViews))
	for _, v := range data.ParentViews {
		st := sdk.CheckState{Code: "delegation_ds_query_failed", Subject: v.Server}
		if v.DSQueryError != "" {
			st.Status = sdk.StatusWarn
			st.Message = fmt.Sprintf("DS query failed: %s", v.DSQueryError)
		} else {
			st.Status = sdk.StatusOK
			st.Message = fmt.Sprintf("%d DS record(s) returned", len(v.DS))
		}
		out = append(out, st)
	}
	return out
}

type dsMatchesDeclaredRule struct{}

func (r *dsMatchesDeclaredRule) Name() string { return "delegation_ds_matches_declared" }
func (r *dsMatchesDeclaredRule) Description() string {
	return "Verifies that the DS RRset served by the parent matches the service's declared DS records"
}
func (r *dsMatchesDeclaredRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ds_mismatch")
	if errState != nil {
		return errState
	}
	declared := dsRecordsToMiekg(data.DeclaredDS)
	var out []sdk.CheckState
	for _, v := range data.ParentViews {
		if v.DSQueryError != "" {
			continue
		}
		got := dsRecordsToMiekg(v.DS)
		if len(declared) == 0 && len(got) == 0 {
			continue
		}
		missing, extra := diffDS(declared, got)
		st := sdk.CheckState{Code: "delegation_ds_mismatch", Subject: v.Server}
		if len(missing) == 0 && len(extra) == 0 {
			st.Status = sdk.StatusOK
			st.Message = "DS RRset matches the declared service"
		} else {
			if len(declared) == 0 {
				st.Status = sdk.StatusWarn
			} else {
				st.Status = sdk.StatusCrit
			}
			st.Message = fmt.Sprintf("DS RRset does not match declared: missing=%d extra=%d", len(missing), len(extra))
			st.Meta = map[string]any{"missing": len(missing), "extra": len(extra)}
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusInfo,
			Code:    "delegation_ds_mismatch",
			Message: "no DS data to compare",
		}}
	}
	return out
}

type dsPresentAtParentRule struct{}

func (r *dsPresentAtParentRule) Name() string { return "delegation_ds_present_at_parent" }
func (r *dsPresentAtParentRule) Description() string {
	return "Flags the case where the service declares DS records but the parent serves none"
}
func (r *dsPresentAtParentRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ds_missing")
	if errState != nil {
		return errState
	}
	if len(data.DeclaredDS) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusInfo,
			Code:    "delegation_ds_missing",
			Message: "service declares no DS records",
		}}
	}
	anyDS := false
	for _, v := range data.ParentViews {
		if v.DSQueryError == "" && len(v.DS) > 0 {
			anyDS = true
			break
		}
	}
	if anyDS {
		return []sdk.CheckState{{
			Status:  sdk.StatusOK,
			Code:    "delegation_ds_missing",
			Message: "parent serves DS records for the delegation",
		}}
	}
	status := sdk.StatusInfo
	if sdk.GetBoolOption(opts, "requireDS", false) {
		status = sdk.StatusCrit
	}
	return []sdk.CheckState{{
		Status:  status,
		Code:    "delegation_ds_missing",
		Message: "service declares DS records but parent serves none",
	}}
}

type dsRRSIGValidityRule struct{}

func (r *dsRRSIGValidityRule) Name() string { return "delegation_ds_rrsig_validity" }
func (r *dsRRSIGValidityRule) Description() string {
	return "Verifies that every RRSIG covering the DS RRset is inside its validity window"
}
func (r *dsRRSIGValidityRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ds_rrsig_invalid")
	if errState != nil {
		return errState
	}
	now := time.Now()
	var out []sdk.CheckState
	for _, v := range data.ParentViews {
		if v.DSQueryError != "" || len(v.DSRRSIGs) == 0 {
			continue
		}
		worst := sdk.StatusOK
		var reason string
		for _, sig := range v.DSRRSIGs {
			probe := &dns.RRSIG{Inception: sig.Inception, Expiration: sig.Expiration}
			if !probe.ValidityPeriod(now) {
				worst = sdk.StatusCrit
				reason = rrsigReason(sig, now)
				break
			}
		}
		st := sdk.CheckState{Code: "delegation_ds_rrsig_invalid", Subject: v.Server, Status: worst}
		if worst == sdk.StatusOK {
			st.Message = "DS RRSIG within validity window"
		} else {
			st.Message = fmt.Sprintf("DS RRSIG: %s", reason)
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusInfo,
			Code:    "delegation_ds_rrsig_invalid",
			Message: "no DS RRSIG to evaluate",
		}}
	}
	return out
}

// rrsigReason distinguishes "not yet valid" from "expired"; miekg's
// ValidityPeriod only returns a bool, so we redo the uint32-wraparound math.
func rrsigReason(sig DSRRSIGObservation, now time.Time) string {
	utc := now.UTC().Unix()
	modi := (int64(sig.Inception) - utc) / year68
	ti := int64(sig.Inception) + modi*year68
	mode := (int64(sig.Expiration) - utc) / year68
	te := int64(sig.Expiration) + mode*year68
	switch {
	case ti > utc:
		return "signature not yet valid"
	case utc > te:
		return "signature expired"
	default:
		return "signature outside its validity window"
	}
}

// ───────────────────────── child-side rules ─────────────────────────

type nsResolvableRule struct{}

func (r *nsResolvableRule) Name() string { return "delegation_ns_resolvable" }
func (r *nsResolvableRule) Description() string {
	return "Verifies that every out-of-bailiwick NS hostname resolves to at least one address"
}
func (r *nsResolvableRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ns_unresolvable")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		if isInBailiwick(c.NSName, data.DelegatedFQDN) {
			continue
		}
		st := sdk.CheckState{Code: "delegation_ns_unresolvable", Subject: c.NSName}
		if c.ResolveError != "" {
			st.Status = sdk.StatusCrit
			st.Message = fmt.Sprintf("cannot resolve NS: %s", c.ResolveError)
		} else {
			st.Status = sdk.StatusOK
			st.Message = fmt.Sprintf("%d address(es)", len(c.Addresses))
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusInfo,
			Code:    "delegation_ns_unresolvable",
			Message: "no out-of-bailiwick NS to resolve",
		}}
	}
	return out
}

type childReachableRule struct{}

func (r *childReachableRule) Name() string { return "delegation_child_reachable" }
func (r *childReachableRule) Description() string {
	return "Verifies that every delegated name server address answers over UDP"
}
func (r *childReachableRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_unreachable")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		for _, a := range c.Addresses {
			subject := fmt.Sprintf("%s (%s)", c.NSName, a.Address)
			st := sdk.CheckState{Code: "delegation_unreachable", Subject: subject}
			if a.UDPError != "" {
				st.Status = sdk.StatusCrit
				st.Message = fmt.Sprintf("UDP SOA query failed: %s", a.UDPError)
			} else {
				st.Status = sdk.StatusOK
				st.Message = "UDP SOA query succeeded"
			}
			out = append(out, st)
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_unreachable",
			Message: "no delegated server address to probe",
		}}
	}
	return out
}

type childAuthoritativeRule struct{}

func (r *childAuthoritativeRule) Name() string { return "delegation_child_authoritative" }
func (r *childAuthoritativeRule) Description() string {
	return "Verifies that every reachable delegated server answers authoritatively (AA bit) for the zone"
}
func (r *childAuthoritativeRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_lame")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		for _, a := range c.Addresses {
			if a.UDPError != "" {
				continue
			}
			subject := fmt.Sprintf("%s (%s)", c.NSName, a.Address)
			st := sdk.CheckState{Code: "delegation_lame", Subject: subject}
			if !a.Authoritative {
				st.Status = sdk.StatusCrit
				st.Message = "server is not authoritative for the zone"
			} else {
				st.Status = sdk.StatusOK
				st.Message = "authoritative answer"
			}
			out = append(out, st)
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_lame",
			Message: "no reachable delegated server to probe",
		}}
	}
	return out
}

type childSOASerialDriftRule struct{}

func (r *childSOASerialDriftRule) Name() string { return "delegation_child_soa_serial_drift" }
func (r *childSOASerialDriftRule) Description() string {
	return "Verifies that all reachable addresses of a name server agree on the SOA serial"
}
func (r *childSOASerialDriftRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_soa_serial_drift")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		seen := map[uint32]bool{}
		for _, a := range c.Addresses {
			if a.SOASerialKnown {
				seen[a.SOASerial] = true
			}
		}
		if len(seen) == 0 {
			continue
		}
		st := sdk.CheckState{Code: "delegation_soa_serial_drift", Subject: c.NSName}
		if len(seen) > 1 {
			serials := make([]string, 0, len(seen))
			for s := range seen {
				serials = append(serials, fmt.Sprintf("%d", s))
			}
			st.Status = sdk.StatusWarn
			st.Message = fmt.Sprintf("SOA serial drift across addresses: %s", strings.Join(serials, ", "))
		} else {
			st.Status = sdk.StatusOK
			st.Message = "all addresses agree on SOA serial"
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_soa_serial_drift",
			Message: "no SOA serial observed",
		}}
	}
	return out
}

type childTCPRule struct{}

func (r *childTCPRule) Name() string { return "delegation_child_tcp" }
func (r *childTCPRule) Description() string {
	return "Verifies that every reachable delegated server also answers over TCP"
}
func (r *childTCPRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_tcp_failed")
	if errState != nil {
		return errState
	}
	requireTCP := sdk.GetBoolOption(opts, "requireTCP", true)
	failStatus := sdk.StatusCrit
	if !requireTCP {
		failStatus = sdk.StatusWarn
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		for _, a := range c.Addresses {
			if a.UDPError != "" {
				continue
			}
			subject := fmt.Sprintf("%s (%s)", c.NSName, a.Address)
			st := sdk.CheckState{Code: "delegation_tcp_failed", Subject: subject}
			if a.TCPError != "" {
				st.Status = failStatus
				st.Message = fmt.Sprintf("TCP SOA query failed: %s", a.TCPError)
			} else {
				st.Status = sdk.StatusOK
				st.Message = "TCP reachable"
			}
			out = append(out, st)
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_tcp_failed",
			Message: "no reachable delegated server to probe",
		}}
	}
	return out
}

type childNSMatchesParentRule struct{}

func (r *childNSMatchesParentRule) Name() string { return "delegation_child_ns_matches_parent" }
func (r *childNSMatchesParentRule) Description() string {
	return "Verifies that the NS RRset served by each delegated server agrees with the parent's view"
}
func (r *childNSMatchesParentRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_ns_drift")
	if errState != nil {
		return errState
	}
	primary := primaryParentView(data.ParentViews)
	if primary == nil {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_ns_drift",
			Message: "no parent NS RRset to compare against",
		}}
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		for _, a := range c.Addresses {
			if a.UDPError != "" || a.ChildNSError != "" {
				continue
			}
			subject := fmt.Sprintf("%s (%s)", c.NSName, a.Address)
			missing, extra := diffStringSets(primary.NS, a.ChildNS)
			st := sdk.CheckState{Code: "delegation_ns_drift", Subject: subject}
			if len(missing) > 0 || len(extra) > 0 {
				st.Status = sdk.StatusWarn
				st.Message = fmt.Sprintf("child NS RRset differs from parent: missing=%v extra=%v", missing, extra)
				st.Meta = map[string]any{"missing": missing, "extra": extra}
			} else {
				st.Status = sdk.StatusOK
				st.Message = "child NS RRset matches parent"
			}
			out = append(out, st)
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_ns_drift",
			Message: "no child NS RRset observed",
		}}
	}
	return out
}

type childGlueMatchesParentRule struct{}

func (r *childGlueMatchesParentRule) Name() string { return "delegation_child_glue_matches_parent" }
func (r *childGlueMatchesParentRule) Description() string {
	return "Verifies that the addresses served by the child for in-bailiwick NS names match the parent glue"
}
func (r *childGlueMatchesParentRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_glue_mismatch")
	if errState != nil {
		return errState
	}
	primary := primaryParentView(data.ParentViews)
	if primary == nil {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_glue_mismatch",
			Message: "no parent glue to compare against",
		}}
	}
	allow := sdk.GetBoolOption(opts, "allowGlueMismatch", false)
	failStatus := sdk.StatusCrit
	if allow {
		failStatus = sdk.StatusWarn
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		if !isInBailiwick(c.NSName, data.DelegatedFQDN) {
			continue
		}
		for _, a := range c.Addresses {
			if a.UDPError != "" {
				continue
			}
			subject := fmt.Sprintf("%s (%s)", c.NSName, a.Address)
			// Extras are allowed: child may have more interfaces than the
			// parent publishes; only missing parent-glue matters.
			missing, _ := diffStringSets(primary.Glue[c.NSName], a.ChildGlueAddrs)
			st := sdk.CheckState{Code: "delegation_glue_mismatch", Subject: subject}
			if len(missing) > 0 {
				st.Status = failStatus
				st.Message = fmt.Sprintf("child addresses for %s differ from parent glue: missing=%v", c.NSName, missing)
				st.Meta = map[string]any{"missing": missing}
			} else {
				st.Status = sdk.StatusOK
				st.Message = "child glue matches parent"
			}
			out = append(out, st)
		}
	}
	// No in-bailiwick NS means there's no glue to compare; stay silent.
	return out
}

// ───────────────────────── DNSSEC rules ─────────────────────────

func parentHasAnyDS(views []ParentView) bool {
	for _, v := range views {
		if len(v.DS) > 0 {
			return true
		}
	}
	return false
}

type dnskeyQueryRule struct{}

func (r *dnskeyQueryRule) Name() string { return "delegation_dnskey_query" }
func (r *dnskeyQueryRule) Description() string {
	return "Verifies that the delegated servers answer DNSKEY queries when the parent publishes DS records"
}
func (r *dnskeyQueryRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_dnskey_query_failed")
	if errState != nil {
		return errState
	}
	if !parentHasAnyDS(data.ParentViews) {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_dnskey_query_failed",
			Message: "parent has no DS records, DNSKEY probe skipped",
		}}
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		for _, a := range c.Addresses {
			if a.UDPError != "" {
				continue
			}
			subject := fmt.Sprintf("%s (%s)", c.NSName, a.Address)
			st := sdk.CheckState{Code: "delegation_dnskey_query_failed", Subject: subject}
			if a.DNSKEYError != "" {
				st.Status = sdk.StatusWarn
				st.Message = fmt.Sprintf("DNSKEY query failed: %s", a.DNSKEYError)
			} else {
				st.Status = sdk.StatusOK
				st.Message = fmt.Sprintf("%d DNSKEY record(s) returned", len(a.DNSKEYs))
			}
			out = append(out, st)
		}
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_dnskey_query_failed",
			Message: "no reachable child server to probe",
		}}
	}
	return out
}

type dnskeyMatchesDSRule struct{}

func (r *dnskeyMatchesDSRule) Name() string { return "delegation_dnskey_matches_ds" }
func (r *dnskeyMatchesDSRule) Description() string {
	return "Verifies that at least one DNSKEY served by the child hashes to one of the DS records at the parent"
}
func (r *dnskeyMatchesDSRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_dnskey_no_match")
	if errState != nil {
		return errState
	}
	if !parentHasAnyDS(data.ParentViews) {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_dnskey_no_match",
			Message: "parent has no DS records, DNSKEY/DS match skipped",
		}}
	}
	var parentDS []*dns.DS
	for _, v := range data.ParentViews {
		if len(v.DS) > 0 {
			parentDS = dsRecordsToMiekg(v.DS)
			break
		}
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		var keys []*dns.DNSKEY
		probed := false
		for _, a := range c.Addresses {
			if len(a.DNSKEYs) > 0 {
				probed = true
				keys = append(keys, dnskeysToMiekg(a.DNSKEYs)...)
			}
		}
		if !probed {
			continue
		}
		st := sdk.CheckState{Code: "delegation_dnskey_no_match", Subject: c.NSName}
		if dsMatchesAnyKey(parentDS, keys) {
			st.Status = sdk.StatusOK
			st.Message = "at least one DNSKEY matches a parent DS record"
		} else {
			st.Status = sdk.StatusCrit
			st.Message = "no DNSKEY served by this NS matches any parent DS record"
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_dnskey_no_match",
			Message: "no DNSKEY observed at any child server",
		}}
	}
	return out
}

type nsHasAuthoritativeAnswerRule struct{}

func (r *nsHasAuthoritativeAnswerRule) Name() string {
	return "delegation_ns_has_authoritative_answer"
}
func (r *nsHasAuthoritativeAnswerRule) Description() string {
	return "Verifies that every delegated NS produced at least one authoritative answer across all its addresses"
}
func (r *nsHasAuthoritativeAnswerRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) []sdk.CheckState {
	data, errState := loadData(ctx, obs, "delegation_no_authoritative_answer")
	if errState != nil {
		return errState
	}
	var out []sdk.CheckState
	for _, c := range data.Children {
		if len(c.Addresses) == 0 {
			continue
		}
		sawAA := false
		for _, a := range c.Addresses {
			if a.UDPError == "" && a.Authoritative {
				sawAA = true
				break
			}
		}
		st := sdk.CheckState{Code: "delegation_no_authoritative_answer", Subject: c.NSName}
		if sawAA {
			st.Status = sdk.StatusOK
			st.Message = "at least one address answered authoritatively"
		} else {
			st.Status = sdk.StatusCrit
			st.Message = "no address of this NS answered authoritatively"
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusUnknown,
			Code:    "delegation_no_authoritative_answer",
			Message: "no delegated NS to probe",
		}}
	}
	return out
}
