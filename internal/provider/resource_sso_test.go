package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccOIDCProviderAndMappings(t *testing.T) {
	testAccPreCheck(t)
	slug := randName("idp")
	cfg := func(name, secret string) string {
		return fmt.Sprintf(`
resource "hallpass_oidc_provider" "p" {
  slug          = %q
  display_name  = %q
  issuer        = "https://login.example.com"
  client_id     = "hallpass"
  client_secret = %q
  groups_claim  = "groups"
  provisioning  = "jit"
  jit = {
    email_domains = ["example.com"]
  }
  enabled = false
}

resource "hallpass_oidc_group_mapping" "admins" {
  provider_id = hallpass_oidc_provider.p.id
  group_value = "hallpass-admins"
  role        = "administrator"
}
`, slug, name, secret)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("Example SSO", "s3cret-1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_oidc_provider.p", "id", idRE("oidc")),
					resource.TestCheckResourceAttr("hallpass_oidc_provider.p", "scopes.#", "3"),
					resource.TestCheckResourceAttr("hallpass_oidc_provider.p", "stepup_fallback", "none"),
					resource.TestMatchResourceAttr("hallpass_oidc_provider.p", "redirect_uri", regexp.MustCompile(`/auth/oidc/callback$`)),
					resource.TestMatchResourceAttr("hallpass_oidc_group_mapping.admins", "id", idRE("ogm")),
				),
			},
			{
				Config:           cfg("Example single sign-on", "s3cret-2"),
				ConfigPlanChecks: expectUpdate("hallpass_oidc_provider.p"),
				Check:            resource.TestCheckResourceAttr("hallpass_oidc_provider.p", "display_name", "Example single sign-on"),
			},
			{ResourceName: "hallpass_oidc_provider.p", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"client_secret"}},
			{ResourceName: "hallpass_oidc_group_mapping.admins", ImportState: true, ImportStateVerify: true,
				ImportStateIdFunc: importID("hallpass_oidc_group_mapping.admins", "provider_id", "id")},
		},
	})
}

func TestAccIntegrationsAndRoutes(t *testing.T) {
	testAccPreCheck(t)
	name := randName("chat")
	cfg := func(teamID string, chats string) string {
		return fmt.Sprintf(`
resource "hallpass_integration" "slack" {
  name = "%s-slack"
  slack = {
    team_id = %q
  }
  secrets = {
    bot_token      = "xoxb-test"
    signing_secret = "signing-test"
  }
}

resource "hallpass_integration" "telegram" {
  name = "%s-telegram"
  telegram = {
    bot_username     = "hallpass_test_bot"
    allowed_chat_ids = [%s]
  }
  secrets = {
    bot_token = "123456789:AAEexampleexampleexampleexample123"
  }
}

resource "hallpass_notification_route" "ops" {
  integration_id = hallpass_integration.slack.id
  destination    = "C0123456789"
  targets        = { all = true }
}
`, name, teamID, name, chats)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("T0123456789", "-1001234567890"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_integration.slack", "webhook_path", regexp.MustCompile(`slack`)),
					resource.TestCheckResourceAttr("hallpass_integration.telegram", "telegram.allowed_chat_ids.#", "1"),
					resource.TestMatchResourceAttr("hallpass_notification_route.ops", "id", idRE("rte")),
					resource.TestCheckResourceAttr("hallpass_notification_route.ops", "targets.all", "true"),
				),
			},
			{
				Config:           cfg("T0987654321", "-1001234567890, -1009876543210"),
				ConfigPlanChecks: expectUpdate("hallpass_integration.slack"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_integration.slack", "slack.team_id", "T0987654321"),
					resource.TestCheckResourceAttr("hallpass_integration.telegram", "telegram.allowed_chat_ids.#", "2"),
				),
			},
			{ResourceName: "hallpass_integration.telegram", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"secrets"}},
			{ResourceName: "hallpass_notification_route.ops", ImportState: true, ImportStateVerify: true},
		},
	})
}
