package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// An API target with its CA, a read profile with GraphQL and deny rules, and a write-only credential that can be
// replaced in place.
func TestAccAPITarget(t *testing.T) {
	testAccPreCheck(t)
	alias := randName("api")
	cfg := func(hosts, secret string) string {
		return fmt.Sprintf(`
resource "hallpass_api_target" "a" {
  alias = %q
  hosts = [%s]
}

resource "hallpass_api_access_profile" "read" {
  server_id = hallpass_api_target.a.id
  alias     = "read"
  rules = [
    { effect = "allow", methods = ["GET", "HEAD"] },
    { effect = "allow", methods = ["POST"], paths = ["/graphql"], graphql = ["query"] },
    { effect = "deny", paths = ["/user/keys/**"] },
  ]
  max_duration = "2h"
}

resource "hallpass_api_credential" "read" {
  role_id = hallpass_api_access_profile.read.id
  type    = "header"
  header  = "X-Api-Key"
  secret  = %q
}
`, alias, hosts, secret)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(`"api.example.com"`, "first-secret-1111"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_api_target.a", "hosts.0", "api.example.com"),
					resource.TestMatchResourceAttr("hallpass_api_target.a", "ca_certificate", regexp.MustCompile(`BEGIN CERTIFICATE`)),
					resource.TestCheckResourceAttr("hallpass_api_access_profile.read", "rules.#", "3"),
					resource.TestCheckResourceAttr("hallpass_api_access_profile.read", "rules.1.graphql.0", "query"),
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "hint", "…1111"),
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "version", "1"),
				),
			},
			{
				Config: cfg(`"api.example.com", "*.uploads.example.com"`, "second-secret-2222"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_api_target.a", "hosts.#", "2"),
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "hint", "…2222"),
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "version", "2"),
				),
			},
			{ResourceName: "hallpass_api_target.a", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_api_access_profile.read", ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestAccAPIProfileRejectsWrongKind(t *testing.T) {
	testAccPreCheck(t)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "hallpass_api_target" "a" {
  alias = %q
  hosts = ["api.example.com"]
}

resource "hallpass_api_access_profile" "bad" {
  server_id = hallpass_api_target.a.id
  alias     = "bad"
  rules     = [{ effect = "deny" }]
}
`, randName("api")),
			ExpectError: regexp.MustCompile(`allow rule`),
		}},
	})
}
