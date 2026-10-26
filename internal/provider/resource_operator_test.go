package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// An Auditor token issued by the provider's Administrator token: usable at once, rotated by triggers, re-issued after
// an out-of-band revocation, and revoked on destroy.
func TestAccAPIToken(t *testing.T) {
	testAccPreCheck(t)
	name := randName("deed")
	cfg := func(rotation string) string {
		return fmt.Sprintf(`
resource "hallpass_api_token" "deed" {
  name          = %q
  role          = "auditor"
  never_expires = true
  triggers      = { rotation = %q }
}

resource "hallpass_api_token" "report" {
  name            = "%s-report"
  role            = "viewer"
  expires_in_days = 30
}
`, name, rotation, name)
	}
	var first, second, secondID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			c := apiClient(t)
			for _, rs := range s.RootModule().Resources {
				if rs.Type != "hallpass_api_token" {
					continue
				}
				tok, err := c.GetAPIToken(context.Background(), rs.Primary.ID)
				if err != nil {
					return err
				}
				if tok.RevokedAt == "" {
					return fmt.Errorf("token %s not revoked", rs.Primary.ID)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: cfg("1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_api_token.deed", "id", idRE("atk")),
					resource.TestMatchResourceAttr("hallpass_api_token.deed", "token", regexp.MustCompile(`^hallpass_at_[A-Za-z0-9_-]{43}$`)),
					resource.TestCheckResourceAttr("hallpass_api_token.deed", "expires_at", ""),
					resource.TestMatchResourceAttr("hallpass_api_token.report", "expires_at", regexp.MustCompile(`^20`)),
					resource.TestMatchResourceAttr("hallpass_api_token.deed", "operator_id", idRE("opr")),
					capture("hallpass_api_token.deed", "token", &first),
					func(*terraform.State) error { return useToken(first, true) },
				),
			},
			{
				Config:           cfg("2"),
				ConfigPlanChecks: expectReplace("hallpass_api_token.deed"),
				Check: resource.ComposeAggregateTestCheckFunc(
					capture("hallpass_api_token.deed", "token", &second),
					capture("hallpass_api_token.deed", "id", &secondID),
					func(*terraform.State) error {
						if first == second {
							return errors.New("rotation kept the token")
						}
						if err := useToken(first, false); err != nil {
							return err
						}
						return useToken(second, true)
					},
				),
			},
			{
				// Revoked outside Terraform: the next plan issues it again.
				PreConfig:        oob(t, func(ctx context.Context, c *client.Client) error { return c.RevokeAPIToken(ctx, secondID) }),
				Config:           cfg("2"),
				ConfigPlanChecks: expectRecreate("hallpass_api_token.deed"),
			},
		},
	})
}

// useToken checks that a token can (or cannot) read the system status.
func useToken(token string, works bool) error {
	c, err := client.New(client.Config{Endpoint: acc.Endpoint, Token: token, UserAgent: "tfacc-token"})
	if err != nil {
		return err
	}
	_, err = c.ListGatewayHostKeys(context.Background())
	switch {
	case works && err != nil:
		return fmt.Errorf("token should work: %w", err)
	case !works && err == nil:
		return errors.New("token should no longer work")
	}
	return nil
}

// Operators with roles and groups, a linked SSO identity and a chat account; destroy disables the operator.
func TestAccOperator(t *testing.T) {
	testAccPreCheck(t)
	email := randName("rita") + "@example.com"
	slug := randName("idp")
	cfg := func(roles, groups string, enabled bool) string {
		return fmt.Sprintf(`
resource "hallpass_oidc_provider" "p" {
  slug          = %q
  display_name  = "Porch"
  issuer        = "https://%s.example.com"
  client_id     = "hallpass"
  client_secret = "s3cret-value-for-tests"
  provisioning  = "jit"
  jit = {
    email_domains = ["example.com"]
  }
  enabled = false
}

resource "hallpass_operator" "rita" {
  email        = %q
  display_name = "Rita"
  roles        = [%s]
  groups       = [%s]
  enabled      = %t
}

resource "hallpass_operator_identity" "rita" {
  operator_id = hallpass_operator.rita.id
  provider_id = hallpass_oidc_provider.p.id
  subject     = "rita-sub-123"
}

resource "hallpass_operator_chat_link" "rita" {
  operator_id      = hallpass_operator.rita.id
  platform         = "telegram"
  workspace        = "hallpass_bot"
  provider_user_id = "424242"
  display          = "@rita"
}
`, slug, slug, email, roles, groups, enabled)
	}
	var opID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			o, err := apiClient(t).GetOperator(context.Background(), opID)
			if err != nil {
				return err
			}
			if o.Enabled || len(o.ManualRoles()) != 0 {
				return fmt.Errorf("operator not disabled: %+v", o)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: cfg(`"auditor"`, `"oncall"`, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_operator.rita", "id", idRE("opr")),
					resource.TestCheckResourceAttr("hallpass_operator.rita", "roles.#", "1"),
					resource.TestCheckResourceAttr("hallpass_operator.rita", "groups.0", "oncall"),
					resource.TestCheckResourceAttr("hallpass_operator.rita", "has_password", "false"),
					resource.TestCheckResourceAttr("hallpass_operator_identity.rita", "issuer", "https://"+slug+".example.com"),
					resource.TestCheckResourceAttr("hallpass_operator_chat_link.rita", "display", "@rita"),
					capture("hallpass_operator.rita", "id", &opID),
				),
			},
			{
				Config:           cfg(`"approver", "viewer"`, "", true),
				ConfigPlanChecks: expectUpdate("hallpass_operator.rita"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_operator.rita", "roles.#", "2"),
					resource.TestCheckResourceAttr("hallpass_operator.rita", "groups.#", "0"),
				),
			},
			{ResourceName: "hallpass_operator.rita", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_operator_identity.rita", ImportState: true, ImportStateVerify: true,
				ImportStateIdFunc: importID("hallpass_operator_identity.rita", "operator_id", "provider_id", "subject")},
			{ResourceName: "hallpass_operator_chat_link.rita", ImportState: true, ImportStateVerify: true,
				ImportStateIdFunc: importID("hallpass_operator_chat_link.rita", "operator_id", "platform", "workspace", "provider_user_id")},
			{
				// Unlinked outside Terraform: the next plan links it again.
				PreConfig: oob(t, func(ctx context.Context, c *client.Client) error {
					return c.UnlinkChat(ctx, opID, "telegram", "hallpass_bot", "424242")
				}),
				Config:           cfg(`"approver", "viewer"`, "", true),
				ConfigPlanChecks: expectRecreate("hallpass_operator_chat_link.rita"),
			},
			{
				// Disabling the operator removes its chat links (HallPass does that on purpose); the next apply links again.
				Config:             cfg(`"approver", "viewer"`, "", false),
				Check:              resource.TestCheckResourceAttr("hallpass_operator.rita", "enabled", "false"),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// A destination collector on a server; a new key replaces (and revokes) the old enrollment.
func TestAccDestinationCollector(t *testing.T) {
	testAccPreCheck(t)
	alias := randName("web")
	key1, key2, key3 := newPublicKey(t, "collector"), newPublicKey(t, "collector2"), newPublicKey(t, "collector3")
	cfg := func(key string) string {
		return fmt.Sprintf(`
resource "hallpass_server" "s" {
  alias   = %q
  address = "127.0.0.1"
  port    = 22
}

resource "hallpass_destination_collector" "c" {
  server_id  = hallpass_server.s.id
  public_key = %q
}

resource "hallpass_destination_collector" "named" {
  server_id  = hallpass_server.s.id
  name       = "auditd"
  public_key = %q
}

data "hallpass_egress" "e" {}
`, alias, key, key3)
	}
	var firstID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(key1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_destination_collector.c", "id", idRE("dac")),
					resource.TestMatchResourceAttr("hallpass_destination_collector.c", "fingerprint", regexp.MustCompile(`^SHA256:`)),
					resource.TestMatchResourceAttr("hallpass_destination_collector.c", "name", regexp.MustCompile(`^collector-[0-9a-f]{12}$`)),
					resource.TestCheckResourceAttr("hallpass_destination_collector.named", "name", "auditd"),
					resource.TestCheckResourceAttr("hallpass_destination_collector.c", "public_key", key1),
					resource.TestCheckResourceAttr("data.hallpass_egress.e", "allow_cidrs.0", "127.0.0.0/8"),
					resource.TestCheckResourceAttr("data.hallpass_egress.e", "source_addresses.#", "0"),
					capture("hallpass_destination_collector.c", "id", &firstID),
				),
			},
			// HallPass stores the key without its comment.
			{ResourceName: "hallpass_destination_collector.c", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"public_key"}},
			{
				Config:           cfg(key2),
				ConfigPlanChecks: expectReplace("hallpass_destination_collector.c"),
				Check: func(*terraform.State) error {
					d, err := apiClient(t).GetDestinationCollector(context.Background(), firstID)
					if err != nil {
						return err
					}
					if d.State != "revoked" {
						return fmt.Errorf("old enrollment %s is %s", firstID, d.State)
					}
					return nil
				},
			},
		},
	})
}
