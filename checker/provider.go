package checker

import (
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

func Provider() sdk.ObservationProvider {
	return &delegationProvider{}
}

type delegationProvider struct{}

func (p *delegationProvider) Key() sdk.ObservationKey {
	return ObservationKeyDelegation
}

// ValidateOptions runs once per provider so each rule doesn't re-check.
func (p *delegationProvider) ValidateOptions(opts sdk.CheckerOptions) error {
	if v, ok := opts["minNameServers"]; ok {
		var f float64
		switch n := v.(type) {
		case float64:
			f = n
		case float32:
			f = float64(n)
		case int:
			f = float64(n)
		case int32:
			f = float64(n)
		case int64:
			f = float64(n)
		case uint:
			f = float64(n)
		case uint32:
			f = float64(n)
		case uint64:
			f = float64(n)
		default:
			return fmt.Errorf("minNameServers must be a number")
		}
		if f < 1 {
			return fmt.Errorf("minNameServers must be >= 1")
		}
	}
	return nil
}
