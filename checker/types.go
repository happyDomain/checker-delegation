package checker

import (
	"encoding/json"

	"github.com/miekg/dns"
)

const ObservationKeyDelegation = "delegation"

// DelegationData is the raw, judgment-free observation produced by Collect.
// Severity classification belongs to the rules, not to the data.
type DelegationData struct {
	DelegatedFQDN string `json:"delegated_fqdn"`
	ParentZone    string `json:"parent_zone"`

	// DeclaredNS/DeclaredDS come from the service definition,
	// lowercased and FQDN-normalized for direct comparison.
	DeclaredNS []string   `json:"declared_ns,omitempty"`
	DeclaredDS []DSRecord `json:"declared_ds,omitempty"`

	ParentDiscoveryError string       `json:"parent_discovery_error,omitempty"`
	ParentNS             []string     `json:"parent_ns,omitempty"`
	ParentViews          []ParentView `json:"parent_views,omitempty"`

	// Children is seeded from the first successful parent view only.
	Children []ChildNSView `json:"children,omitempty"`
}

type ParentView struct {
	Server       string               `json:"server"`
	UDPNSError   string               `json:"udp_ns_error,omitempty"`
	TCPNSError   string               `json:"tcp_ns_error,omitempty"`
	NS           []string             `json:"ns,omitempty"`
	Glue         map[string][]string  `json:"glue,omitempty"`
	DSQueryError string               `json:"ds_query_error,omitempty"`
	DS           []DSRecord           `json:"ds,omitempty"`
	DSRRSIGs     []DSRRSIGObservation `json:"ds_rrsigs,omitempty"`
}

type ChildNSView struct {
	NSName       string             `json:"ns_name"`
	ResolveError string             `json:"resolve_error,omitempty"`
	Addresses    []ChildAddressView `json:"addresses,omitempty"`
}

type ChildAddressView struct {
	Address        string         `json:"address"`
	Server         string         `json:"server"`
	UDPError       string         `json:"udp_error,omitempty"`
	Authoritative  bool           `json:"authoritative"`
	SOASerial      uint32         `json:"soa_serial,omitempty"`
	SOASerialKnown bool           `json:"soa_serial_known,omitempty"`
	TCPError       string         `json:"tcp_error,omitempty"`
	ChildNS        []string       `json:"child_ns,omitempty"`
	ChildNSError   string         `json:"child_ns_error,omitempty"`
	ChildGlueAddrs []string       `json:"child_glue_addrs,omitempty"`
	DNSKEYError    string         `json:"dnskey_error,omitempty"`
	DNSKEYs        []DNSKEYRecord `json:"dnskeys,omitempty"`
}

// DSRecord keeps both the rendered text (for humans) and the structured
// fields (for direct comparison).
type DSRecord struct {
	Text       string `json:"text"`
	KeyTag     uint16 `json:"keytag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

func (d DSRecord) ToMiekg() *dns.DS {
	return &dns.DS{
		KeyTag:     d.KeyTag,
		Algorithm:  d.Algorithm,
		DigestType: d.DigestType,
		Digest:     d.Digest,
	}
}

func NewDSRecord(d *dns.DS) DSRecord {
	return DSRecord{
		Text:       d.String(),
		KeyTag:     d.KeyTag,
		Algorithm:  d.Algorithm,
		DigestType: d.DigestType,
		Digest:     d.Digest,
	}
}

// DNSKEYRecord keeps the fields needed to recompute DS digests.
type DNSKEYRecord struct {
	Name      string `json:"name"`
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// ToMiekg restores miekg form so k.ToDS is callable.
func (k DNSKEYRecord) ToMiekg() *dns.DNSKEY {
	name := k.Name
	if name == "" {
		name = "."
	}
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     k.Flags,
		Protocol:  k.Protocol,
		Algorithm: k.Algorithm,
		PublicKey: k.PublicKey,
	}
}

func NewDNSKEYRecord(k *dns.DNSKEY) DNSKEYRecord {
	return DNSKEYRecord{
		Name:      k.Hdr.Name,
		Flags:     k.Flags,
		Protocol:  k.Protocol,
		Algorithm: k.Algorithm,
		PublicKey: k.PublicKey,
	}
}

// DSRRSIGObservation: rules judge validity, not Collect.
type DSRRSIGObservation struct {
	Inception  uint32 `json:"inception"`
	Expiration uint32 `json:"expiration"`
}

// delegationService mirrors abstract.Delegation locally so this checker
// avoids importing the (heavy) happyDomain server module.
type delegationService struct {
	NameServers []*dns.NS `json:"ns"`
	DS          []*dns.DS `json:"ds"`
}

// serviceMessage mirrors happyDomain's envelope; only the embedded JSON
// is used downstream.
type serviceMessage struct {
	Type    string          `json:"_svctype"`
	Service json.RawMessage `json:"Service"`
}
