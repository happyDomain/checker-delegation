package checker

import (
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Version is overridden at link-time by CI: -ldflags "-X ...Version=1.2.3".
var Version = "built-in"

func (p *delegationProvider) Definition() *sdk.CheckerDefinition {
	return &sdk.CheckerDefinition{
		ID:      "delegation",
		Name:    "DNS delegation",
		Version: Version,
		Availability: sdk.CheckerAvailability{
			ApplyToService:  true,
			LimitToServices: []string{"abstract.Delegation"},
		},
		ObservationKeys: []sdk.ObservationKey{ObservationKeyDelegation},
		Options: sdk.CheckerOptionsDocumentation{
			UserOpts: []sdk.CheckerOptionDocumentation{
				{
					Id:          "requireDS",
					Type:        "bool",
					Label:       "Require DS at parent",
					Description: "When enabled, missing DS records at the parent are treated as a critical issue (otherwise informational).",
					Default:     false,
				},
				{
					Id:          "requireTCP",
					Type:        "bool",
					Label:       "Require DNS over TCP",
					Description: "When enabled, name servers that fail to answer over TCP are reported as critical (otherwise as warning).",
					Default:     true,
				},
				{
					Id:          "minNameServers",
					Type:        "uint",
					Label:       "Minimum number of name servers",
					Description: "Below this count, the delegation is reported as a warning (RFC 1034 recommends at least 2).",
					Default:     float64(2),
				},
				{
					Id:          "allowGlueMismatch",
					Type:        "bool",
					Label:       "Allow glue mismatches",
					Description: "When disabled, glue/address mismatches between parent and child are reported as critical.",
					Default:     false,
				},
			},
			DomainOpts: []sdk.CheckerOptionDocumentation{
				{
					Id:       "domain_name",
					Label:    "Parent domain name",
					AutoFill: sdk.AutoFillDomainName,
				},
				{
					Id:       "subdomain",
					Label:    "Subdomain",
					AutoFill: sdk.AutoFillSubdomain,
				},
			},
			ServiceOpts: []sdk.CheckerOptionDocumentation{
				{
					Id:       "service",
					Label:    "Service",
					AutoFill: sdk.AutoFillService,
				},
			},
		},
		Rules:         Rules(),
		HasHTMLReport: true,
		HasMetrics:    true,
		Interval: &sdk.CheckIntervalSpec{
			Min:     5 * time.Minute,
			Max:     24 * time.Hour,
			Default: 1 * time.Hour,
		},
	}
}
