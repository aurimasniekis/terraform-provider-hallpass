package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
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

// A write-only secret never reaches plan or state; it is sent on create and when secret_wo_version changes.
func TestAccAPICredentialWriteOnly(t *testing.T) {
	testAccPreCheck(t)
	alias := randName("api")
	cfg := func(secret string, version int) string {
		return fmt.Sprintf(`
resource "hallpass_api_target" "a" {
  alias = %q
  hosts = ["api.example.com"]
}

resource "hallpass_api_access_profile" "read" {
  server_id = hallpass_api_target.a.id
  alias     = "read"
  rules     = [{ effect = "allow", methods = ["GET"] }]
}

resource "hallpass_api_credential" "read" {
  role_id           = hallpass_api_access_profile.read.id
  type              = "bearer"
  secret_wo         = %q
  secret_wo_version = %d
}
`, alias, secret, version)
	}
	noSecret := resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckNoResourceAttr("hallpass_api_credential.read", "secret_wo"),
		resource.TestCheckNoResourceAttr("hallpass_api_credential.read", "secret"),
	)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		Steps: []resource.TestStep{
			{
				Config: cfg("first-secret-1111", 1),
				Check: resource.ComposeAggregateTestCheckFunc(noSecret,
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "hint", "…1111"),
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "version", "1")),
			},
			{
				// A new value without a new version is not sent (Terraform cannot see it change).
				Config:   cfg("second-secret-2222", 1),
				PlanOnly: true,
			},
			{
				Config: cfg("second-secret-2222", 2),
				Check: resource.ComposeAggregateTestCheckFunc(noSecret,
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "hint", "…2222"),
					resource.TestCheckResourceAttr("hallpass_api_credential.read", "version", "2")),
			},
		},
	})
}

func TestAccAPICredentialNeedsOneSecret(t *testing.T) {
	testAccPreCheck(t)
	for _, c := range []struct{ secrets, err string }{
		{``, `exactly one of secret and secret_wo`},
		{`secret = "a"` + "\n" + `secret_wo = "b"` + "\n" + `secret_wo_version = 1`, `exactly one of secret and secret_wo`},
		{`secret_wo = "b"`, `secret_wo needs secret_wo_version`},
		{`secret = "a"` + "\n" + `secret_wo_version = 1`, `only applies to secret_wo`},
	} {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
			Steps: []resource.TestStep{{
				Config: `
resource "hallpass_api_credential" "x" {
  role_id = "rol_01hzxv3k4f8m9q2r5t7w0y6c1a"
  type    = "bearer"
  ` + c.secrets + `
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(c.err),
			}},
		})
	}
}
