// Command terraform-provider-hallpass is the Terraform provider for HallPass, a terminating SSH gateway for AI agents.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=…").
var version = "dev"

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name hallpass

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/aurimasniekis/hallpass",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
