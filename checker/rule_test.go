package checker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/miekg/dns"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// fakeObs is a tiny ObservationGetter that serves a single pre-built
// DelegationData payload for the delegation key.
type fakeObs struct {
	data *DelegationData
	err  error
}

func (f *fakeObs) Get(_ context.Context, key sdk.ObservationKey, dest any) error {
	if f.err != nil {
		return f.err
	}
	if key != ObservationKeyDelegation {
		return &errString{"unexpected key " + string(key)}
	}
	raw, err := json.Marshal(f.data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

func (f *fakeObs) GetRelated(_ context.Context, _ sdk.ObservationKey) ([]sdk.RelatedObservation, error) {
	return nil, nil
}

type errString struct{ s string }

func (e *errString) Error() string { return e.s }

// statusByCode indexes states by Code, asserting one state per code.
func statusByCode(t *testing.T, states []sdk.CheckState) map[string]sdk.CheckState {
	t.Helper()
	out := map[string]sdk.CheckState{}
	for _, s := range states {
		out[s.Code+"|"+s.Subject] = s
	}
	return out
}

func evalRule(t *testing.T, r sdk.CheckRule, data *DelegationData, opts sdk.CheckerOptions) []sdk.CheckState {
	t.Helper()
	if opts == nil {
		opts = sdk.CheckerOptions{}
	}
	return r.Evaluate(context.Background(), &fakeObs{data: data}, opts)
}

func TestMinNameServersRule(t *testing.T) {
	r := &minNameServersRule{}

	t.Run("warn when below default minimum", func(t *testing.T) {
		states := evalRule(t, r, &DelegationData{DeclaredNS: []string{"a."}}, nil)
		if len(states) != 1 || states[0].Status != sdk.StatusWarn {
			t.Fatalf("want one Warn state, got %+v", states)
		}
	})
	t.Run("ok when at minimum", func(t *testing.T) {
		states := evalRule(t, r, &DelegationData{DeclaredNS: []string{"a.", "b."}}, nil)
		if len(states) != 1 || states[0].Status != sdk.StatusOK {
			t.Fatalf("want one OK state, got %+v", states)
		}
	})
	t.Run("respects custom minimum", func(t *testing.T) {
		opts := sdk.CheckerOptions{"minNameServers": float64(3)}
		states := evalRule(t, r, &DelegationData{DeclaredNS: []string{"a.", "b."}}, opts)
		if states[0].Status != sdk.StatusWarn {
			t.Fatalf("want Warn with min=3 and 2 NS, got %+v", states)
		}
	})
}

func TestParentDiscoveredRule(t *testing.T) {
	r := &parentDiscoveredRule{}
	cases := []struct {
		name string
		data *DelegationData
		want sdk.Status
	}{
		{"discovery error", &DelegationData{ParentDiscoveryError: "boom"}, sdk.StatusCrit},
		{"no parent ns", &DelegationData{}, sdk.StatusCrit},
		{"ok", &DelegationData{ParentNS: []string{"1.2.3.4:53"}}, sdk.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			states := evalRule(t, r, tc.data, nil)
			if len(states) != 1 || states[0].Status != tc.want {
				t.Fatalf("want %v, got %+v", tc.want, states)
			}
		})
	}
}

func TestNSMatchesDeclaredRule(t *testing.T) {
	r := &nsMatchesDeclaredRule{}
	data := &DelegationData{
		DelegatedFQDN: "www.example.com.",
		DeclaredNS:    []string{"ns1.example.net.", "ns2.example.net."},
		ParentViews: []ParentView{
			{Server: "p1:53", NS: []string{"ns1.example.net.", "ns2.example.net."}}, // match
			{Server: "p2:53", NS: []string{"ns1.example.net.", "ns3.example.net."}}, // mismatch
			{Server: "p3:53", UDPNSError: "timeout"},                                // skipped
		},
	}
	states := evalRule(t, r, data, nil)
	idx := statusByCode(t, states)
	if s := idx["delegation_ns_mismatch|p1:53"]; s.Status != sdk.StatusOK {
		t.Errorf("p1: want OK, got %+v", s)
	}
	if s := idx["delegation_ns_mismatch|p2:53"]; s.Status != sdk.StatusCrit {
		t.Errorf("p2: want Crit, got %+v", s)
	}
	if _, ok := idx["delegation_ns_mismatch|p3:53"]; ok {
		t.Errorf("p3 should be skipped, got %+v", idx)
	}
}

func TestInBailiwickGlueRule(t *testing.T) {
	r := &inBailiwickGlueRule{}
	data := &DelegationData{
		DelegatedFQDN: "example.com.",
		ParentViews: []ParentView{{
			Server: "p:53",
			NS:     []string{"ns1.example.com.", "ns2.elsewhere.net."},
			Glue: map[string][]string{
				"ns1.example.com.": {"192.0.2.1"},
			},
		}},
	}
	states := evalRule(t, r, data, nil)

	var sawOK, sawMissing, sawOOB bool
	for _, s := range states {
		switch {
		case strings.HasPrefix(s.Subject, "ns1.example.com."):
			if s.Status == sdk.StatusOK {
				sawOK = true
			}
		case strings.HasPrefix(s.Subject, "ns2.elsewhere.net."):
			sawOOB = true // out-of-bailiwick: rule must not emit a state for it
		}
		if s.Status == sdk.StatusCrit {
			sawMissing = true
		}
	}
	if !sawOK {
		t.Error("expected OK state for in-bailiwick NS with glue")
	}
	if sawMissing {
		t.Error("did not expect Crit (no in-bailiwick NS is missing glue)")
	}
	if sawOOB {
		t.Error("out-of-bailiwick NS must be ignored by inBailiwickGlueRule")
	}
}

func TestUnnecessaryGlueRule(t *testing.T) {
	r := &unnecessaryGlueRule{}
	data := &DelegationData{
		DelegatedFQDN: "example.com.",
		ParentViews: []ParentView{{
			Server: "p:53",
			NS:     []string{"ns1.elsewhere.net."},
			Glue:   map[string][]string{"ns1.elsewhere.net.": {"192.0.2.5"}},
		}},
	}
	states := evalRule(t, r, data, nil)
	if len(states) != 1 || states[0].Status != sdk.StatusWarn {
		t.Fatalf("want single Warn, got %+v", states)
	}
}

func TestDSPresentAtParentRule_RequireDS(t *testing.T) {
	r := &dsPresentAtParentRule{}
	data := &DelegationData{
		DeclaredDS:  []DSRecord{{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "AAAA"}},
		ParentViews: []ParentView{{Server: "p:53"}}, // no DS at parent
	}
	t.Run("default is informational", func(t *testing.T) {
		states := evalRule(t, r, data, nil)
		if states[0].Status != sdk.StatusInfo {
			t.Fatalf("want Info, got %+v", states)
		}
	})
	t.Run("requireDS escalates to Crit", func(t *testing.T) {
		states := evalRule(t, r, data, sdk.CheckerOptions{"requireDS": true})
		if states[0].Status != sdk.StatusCrit {
			t.Fatalf("want Crit with requireDS, got %+v", states)
		}
	})
}

func TestChildAuthoritativeRule(t *testing.T) {
	r := &childAuthoritativeRule{}
	data := &DelegationData{
		Children: []ChildNSView{{
			NSName: "ns1.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.1", Authoritative: true},
				{Address: "192.0.2.2", Authoritative: false},
				{Address: "192.0.2.3", UDPError: "timeout"}, // skipped
			},
		}},
	}
	states := evalRule(t, r, data, nil)
	if len(states) != 2 {
		t.Fatalf("want 2 states (skip the UDP failure), got %d: %+v", len(states), states)
	}
	var foundCrit bool
	for _, s := range states {
		if s.Status == sdk.StatusCrit {
			foundCrit = true
		}
	}
	if !foundCrit {
		t.Error("expected at least one Crit (the lame address)")
	}
}

func TestChildSOASerialDriftRule(t *testing.T) {
	r := &childSOASerialDriftRule{}
	data := &DelegationData{
		Children: []ChildNSView{{
			NSName: "ns1.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.1", SOASerial: 1, SOASerialKnown: true},
				{Address: "192.0.2.2", SOASerial: 2, SOASerialKnown: true},
			},
		}, {
			NSName: "ns2.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.3", SOASerial: 7, SOASerialKnown: true},
				{Address: "192.0.2.4", SOASerial: 7, SOASerialKnown: true},
			},
		}},
	}
	states := evalRule(t, r, data, nil)
	if len(states) != 2 {
		t.Fatalf("want 2 states, got %d", len(states))
	}
	bySubject := map[string]sdk.Status{}
	for _, s := range states {
		bySubject[s.Subject] = s.Status
	}
	if bySubject["ns1.example.com."] != sdk.StatusWarn {
		t.Errorf("ns1 drift: want Warn, got %v", bySubject["ns1.example.com."])
	}
	if bySubject["ns2.example.com."] != sdk.StatusOK {
		t.Errorf("ns2 agreement: want OK, got %v", bySubject["ns2.example.com."])
	}
}

func TestChildTCPRule_OptionToggle(t *testing.T) {
	r := &childTCPRule{}
	data := &DelegationData{
		Children: []ChildNSView{{
			NSName: "ns1.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.1", TCPError: "connection refused"},
			},
		}},
	}
	t.Run("default requireTCP=true → Crit", func(t *testing.T) {
		states := evalRule(t, r, data, nil)
		if states[0].Status != sdk.StatusCrit {
			t.Fatalf("want Crit, got %+v", states)
		}
	})
	t.Run("requireTCP=false → Warn", func(t *testing.T) {
		states := evalRule(t, r, data, sdk.CheckerOptions{"requireTCP": false})
		if states[0].Status != sdk.StatusWarn {
			t.Fatalf("want Warn, got %+v", states)
		}
	})
}

func TestChildGlueMatchesParentRule(t *testing.T) {
	r := &childGlueMatchesParentRule{}
	data := &DelegationData{
		DelegatedFQDN: "example.com.",
		ParentViews: []ParentView{{
			Server: "p:53",
			NS:     []string{"ns1.example.com."},
			Glue:   map[string][]string{"ns1.example.com.": {"192.0.2.1", "192.0.2.2"}},
		}},
		Children: []ChildNSView{{
			NSName: "ns1.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.1", ChildGlueAddrs: []string{"192.0.2.1"}}, // missing .2 → mismatch
			},
		}},
	}
	t.Run("default → Crit", func(t *testing.T) {
		states := evalRule(t, r, data, nil)
		if states[0].Status != sdk.StatusCrit {
			t.Fatalf("want Crit, got %+v", states)
		}
	})
	t.Run("allowGlueMismatch → Warn", func(t *testing.T) {
		states := evalRule(t, r, data, sdk.CheckerOptions{"allowGlueMismatch": true})
		if states[0].Status != sdk.StatusWarn {
			t.Fatalf("want Warn, got %+v", states)
		}
	})
}

func TestNSHasAuthoritativeAnswerRule(t *testing.T) {
	r := &nsHasAuthoritativeAnswerRule{}
	data := &DelegationData{
		Children: []ChildNSView{
			{
				NSName: "ok.example.com.",
				Addresses: []ChildAddressView{
					{Address: "192.0.2.1", Authoritative: false},
					{Address: "192.0.2.2", Authoritative: true},
				},
			},
			{
				NSName: "lame.example.com.",
				Addresses: []ChildAddressView{
					{Address: "192.0.2.3", Authoritative: false},
				},
			},
		},
	}
	states := evalRule(t, r, data, nil)
	bySubject := map[string]sdk.Status{}
	for _, s := range states {
		bySubject[s.Subject] = s.Status
	}
	if bySubject["ok.example.com."] != sdk.StatusOK {
		t.Errorf("ok.example.com.: want OK, got %v", bySubject["ok.example.com."])
	}
	if bySubject["lame.example.com."] != sdk.StatusCrit {
		t.Errorf("lame.example.com.: want Crit, got %v", bySubject["lame.example.com."])
	}
}

func TestDNSKEYMatchesDSRule_Match(t *testing.T) {
	// Build a key, derive its DS, and verify the rule passes when child serves
	// that key and parent serves that DS.
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAcMnWBKLuvG/LwnPVykcmpvnntwxfshHlHRhlY0F3oz8AMcuF8gw" +
			"2Ge56vG9oqVxTzHl4Ss2dEqCQOjFlOVo+pa3JwIO1lUzbQ==",
	}
	ds := key.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("derive DS")
	}

	data := &DelegationData{
		ParentViews: []ParentView{{Server: "p:53", DS: []DSRecord{NewDSRecord(ds)}}},
		Children: []ChildNSView{{
			NSName: "ns1.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.1", DNSKEYs: []DNSKEYRecord{NewDNSKEYRecord(key)}},
			},
		}},
	}
	r := &dnskeyMatchesDSRule{}
	states := evalRule(t, r, data, nil)
	if len(states) != 1 || states[0].Status != sdk.StatusOK {
		t.Fatalf("want OK match, got %+v", states)
	}
}

func TestDNSKEYMatchesDSRule_NoMatch(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAcMnWBKLuvG/LwnPVykcmpvnntwxfshHlHRhlY0F3oz8AMcuF8gw" +
			"2Ge56vG9oqVxTzHl4Ss2dEqCQOjFlOVo+pa3JwIO1lUzbQ==",
	}
	bogus := &dns.DS{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "00"}
	data := &DelegationData{
		ParentViews: []ParentView{{Server: "p:53", DS: []DSRecord{NewDSRecord(bogus)}}},
		Children: []ChildNSView{{
			NSName: "ns1.example.com.",
			Addresses: []ChildAddressView{
				{Address: "192.0.2.1", DNSKEYs: []DNSKEYRecord{NewDNSKEYRecord(key)}},
			},
		}},
	}
	states := evalRule(t, (&dnskeyMatchesDSRule{}), data, nil)
	if len(states) != 1 || states[0].Status != sdk.StatusCrit {
		t.Fatalf("want Crit, got %+v", states)
	}
}

func TestRulesReturnsAllRules(t *testing.T) {
	rules := Rules()
	if len(rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	// Every rule must have a non-empty name and description, and must be
	// safely evaluable against an empty DelegationData (no panics).
	seen := map[string]bool{}
	for _, r := range rules {
		if r.Name() == "" {
			t.Errorf("rule %T has empty name", r)
		}
		if r.Description() == "" {
			t.Errorf("rule %s has empty description", r.Name())
		}
		if seen[r.Name()] {
			t.Errorf("duplicate rule name: %s", r.Name())
		}
		seen[r.Name()] = true

		states := r.Evaluate(context.Background(), &fakeObs{data: &DelegationData{}}, sdk.CheckerOptions{})
		if len(states) == 0 {
			t.Errorf("rule %s returned no states for empty data", r.Name())
		}
	}
}

func TestLoadDataPropagatesError(t *testing.T) {
	r := &minNameServersRule{}
	states := r.Evaluate(context.Background(), &fakeObs{err: &errString{"boom"}}, sdk.CheckerOptions{})
	if len(states) != 1 || states[0].Status != sdk.StatusError {
		t.Fatalf("want single Error state, got %+v", states)
	}
}
