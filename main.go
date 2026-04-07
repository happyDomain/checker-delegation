package main

import (
	"flag"
	"log"

	delegation "git.happydns.org/checker-delegation/checker"
	"git.happydns.org/checker-sdk-go/checker/server"
)

var listenAddr = flag.String("listen", ":8080", "HTTP listen address")

// Version is overridden at link time: -ldflags "-X main.Version=1.2.3".
var Version = "custom-build"

func main() {
	flag.Parse()

	delegation.Version = Version

	srv := server.New(delegation.Provider())
	if err := srv.ListenAndServe(*listenAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
