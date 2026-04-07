// Command plugin is the happyDomain Go-plugin entrypoint, loaded at runtime.
package main

import (
	delegation "git.happydns.org/checker-delegation/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Version is overridden at link time: -ldflags "-X main.Version=1.2.3".
var Version = "custom-build"

// NewCheckerPlugin is the symbol happyDomain resolves on plugin load.
func NewCheckerPlugin() (*sdk.CheckerDefinition, sdk.ObservationProvider, error) {
	delegation.Version = Version
	prvd := delegation.Provider()
	return prvd.(sdk.CheckerDefinitionProvider).Definition(), prvd, nil
}
