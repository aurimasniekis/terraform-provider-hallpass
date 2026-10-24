package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// Policy and approver rules with every selector form, the operator data source, and the installation-wide settings.
func TestAccPolicyAndSettings(t *testing.T) {
	testAccPreCheck(t)
	alias := randName("db")
	cfg := func(level, autoMax string, prohibit bool) string {
		return fmt.Sprintf(`
resource "hallpass_server" "s" {
  alias   = %q
  address = "127.0.0.1"
  labels  = { tier = "db" }
}

resource "hallpass_policy_rule" "sre" {
  name     = "SRE on databases"
  effect   = "allow"
  level    = %q
  subjects = { agent_groups = ["sre"] }
  targets  = { servers = [hallpass_server.s.id] }
  roles    = { names = ["inspect", "maintenance"] }
  max_duration      = "4h"
  %s
  require_reason = false
}

resource "hallpass_policy_rule" "deny" {
  name   = "No release bot on databases"
  effect = "deny"
  subjects = {
    agent_labels = {
      match_expressions = [{ key = "team", operator = "In", values = ["release"] }]
    }
  }
  targets = { server_labels = { match_labels = { tier = "db" } } }
  roles   = { all = true }
}

data "hallpass_operator" "ada" {
  email = %q
}

resource "hallpass_approver_rule" "dbas" {
  name      = "Ada approves databases"
  operators = { operators = [data.hallpass_operator.ada.id] }
  targets   = { server_groups = ["prod-db"] }
  roles     = { all = true }
  max_duration = "1h"
}

resource "hallpass_self_approval" "this" {
  prohibit_self_approval = %t
}

data "hallpass_gateway_host_keys" "gw" {
  host = "hallpass.example.com"
  port = 2222
}
`, alias, level, autoMax, acc.AdminEmail, prohibit)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			sa, err := apiClient(t).GetSelfApproval(context.Background())
			if err != nil || !sa.ProhibitSelfApproval {
				return fmt.Errorf("self-approval default not restored: %+v: %w", sa, err)
			}
			return checkGone(t, "hallpass_policy_rule", func(ctx context.Context, c *client.Client, a map[string]string) error {
				_, err := c.GetPolicyRule(ctx, a["id"])
				return err
			})(s)
		},
		Steps: []resource.TestStep{
			{
				Config: cfg("requestable", "", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_policy_rule.sre", "id", idRE("pol")),
					resource.TestCheckResourceAttr("hallpass_policy_rule.sre", "subjects.all", "false"),
					resource.TestCheckResourceAttr("hallpass_policy_rule.sre", "roles.names.#", "2"),
					resource.TestCheckResourceAttr("hallpass_policy_rule.sre", "require_reason", "false"),
					resource.TestCheckResourceAttr("hallpass_policy_rule.deny", "require_reason", "true"),
					resource.TestCheckResourceAttr("hallpass_policy_rule.deny", "targets.server_labels.match_labels.tier", "db"),
					resource.TestMatchResourceAttr("data.hallpass_operator.ada", "id", idRE("opr")),
					resource.TestCheckResourceAttr("hallpass_approver_rule.dbas", "max_duration", "1h"),
					resource.TestCheckResourceAttr("hallpass_self_approval.this", "prohibit_self_approval", "false"),
					resource.TestMatchResourceAttr("data.hallpass_gateway_host_keys.gw", "known_hosts",
						regexp.MustCompile(`^\[hallpass\.example\.com\]:2222 ssh-ed25519 `)),
				),
			},
			{
				Config:           cfg("auto_approve", `auto_max_duration = "30m"`, true),
				ConfigPlanChecks: expectUpdate("hallpass_policy_rule.sre"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_policy_rule.sre", "level", "auto_approve"),
					resource.TestCheckResourceAttr("hallpass_policy_rule.sre", "auto_max_duration", "30m"),
					resource.TestCheckResourceAttr("hallpass_self_approval.this", "prohibit_self_approval", "true"),
				),
			},
			{ResourceName: "hallpass_policy_rule.sre", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_policy_rule.deny", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_approver_rule.dbas", ImportState: true, ImportStateVerify: true},
		},
	})
}

// HallPass refuses to turn off password sign-in before a single sign-on test login, so a broken SSO setup cannot lock
// everyone out; the provider surfaces that refusal.
func TestAccAuthSettingsRefusesLockout(t *testing.T) {
	testAccPreCheck(t)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      `resource "hallpass_auth_settings" "a" { local_login_disabled = true }`,
				ExpectError: regexp.MustCompile(`Cannot change sign-in settings`),
			},
			{
				Config: `resource "hallpass_auth_settings" "a" { local_login_disabled = false }`,
				Check:  resource.TestCheckResourceAttr("hallpass_auth_settings.a", "local_login_disabled", "false"),
			},
		},
	})
}
