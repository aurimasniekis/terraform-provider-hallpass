package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// A git remote with a pinned host key, a read profile and a push profile with push rules and a login key whose
// bare public key is what a git host takes.
func TestAccGitRemoteProfiles(t *testing.T) {
	testAccPreCheck(t)
	alias := randName("forge")
	cfg := func(branches string, forcePush bool) string {
		return fmt.Sprintf(`
resource "hallpass_git_remote" "g" {
  alias       = %q
  description = "Company git server"
  address     = %q
  port        = %d
}

resource "hallpass_host_key" "g" {
  server_id  = hallpass_git_remote.g.id
  public_key = %q
}

resource "hallpass_git_access_profile" "read" {
  server_id    = hallpass_git_remote.g.id
  alias        = "acme-read"
  repositories = ["acme/**"]
}

resource "hallpass_git_access_profile" "push" {
  server_id          = hallpass_git_remote.g.id
  alias              = "acme-push"
  repositories       = ["acme/{api,web}"]
  allow_push         = true
  branches           = [%s]
  protected_branches = ["main"]
  allow_force_push   = %t
  approvals_required = 2
  max_duration       = "2h"
}

resource "hallpass_login_key" "push" {
  role_id = hallpass_git_access_profile.push.id
}

resource "hallpass_login_key_activation" "push" {
  role_id      = hallpass_git_access_profile.push.id
  login_key_id = hallpass_login_key.push.id
  depends_on   = [hallpass_host_key.g]
}
`, alias, acc.DestHost, acc.DestPort, acc.DestHostKey, branches, forcePush)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(`"agent/**"`, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_git_remote.g", "environment", ""),
					resource.TestCheckResourceAttr("hallpass_git_access_profile.read", "allow_push", "false"),
					resource.TestCheckResourceAttr("hallpass_git_access_profile.read", "remote_user", "git"),
					resource.TestCheckNoResourceAttr("hallpass_git_access_profile.read", "branches"),
					resource.TestCheckResourceAttr("hallpass_git_access_profile.push", "branches.#", "1"),
					resource.TestCheckResourceAttr("hallpass_git_access_profile.push", "max_duration", "2h"),
					resource.TestMatchResourceAttr("hallpass_login_key.push", "public_key", regexp.MustCompile(`^ssh-ed25519 \S+ hallpass:`+alias+`/acme-push$`)),
					resource.TestCheckResourceAttr("hallpass_login_key_activation.push", "state", "active"),
				),
			},
			{
				Config:           cfg(`"agent/**", "release/*"`, true),
				ConfigPlanChecks: expectUpdate("hallpass_git_access_profile.push"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_git_access_profile.push", "branches.#", "2"),
					resource.TestCheckResourceAttr("hallpass_git_access_profile.push", "allow_force_push", "true"),
				),
			},
			{ResourceName: "hallpass_git_remote.g", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_git_access_profile.push", ImportState: true, ImportStateVerify: true},
			{
				// A server role cannot be managed as a git profile and vice versa.
				ResourceName: "hallpass_role.wrong", ImportState: true, Config: cfg(`"agent/**", "release/*"`, true) + `
resource "hallpass_role" "wrong" {
  server_id   = hallpass_git_remote.g.id
  alias       = "acme-read"
  remote_user = "git"
}
`,
				ImportStateIdFunc: importID("hallpass_git_access_profile.read", "id"),
				ExpectError:       regexp.MustCompile(`manage\s+it\s+with\s+hallpass_git_access_profile`),
			},
		},
	})
}

func TestAccGitProfileValidation(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "hallpass" {
  endpoint = "https://hallpass.example.com"
  token    = "hallpass_at_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
}
resource "hallpass_git_access_profile" "p" {
  server_id    = "srv_01m5qh1t09e4jbmeys0q0bjz8j"
  alias        = "x"
  repositories = ["acme/*"]
  branches     = ["agent/**"]
}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`branches only applies when allow_push is true`),
			},
		},
	})
}
