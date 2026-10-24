package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// A server with a pinned host key, a role, a login key that is test-logged-in and activated against the loopback
// SSH destination, and the data sources that read them back.
func TestAccServerRoleLoginKey(t *testing.T) {
	testAccPreCheck(t)
	alias := randName("web")
	cfg := func(desc, maxDur string, roleEnabled bool, caps, rotation string) string {
		return fmt.Sprintf(`
resource "hallpass_server" "s" {
  alias       = %q
  description = %q
  environment = "production"
  address     = %q
  port        = %d
  groups      = ["prod-web"]
  labels      = { tier = "web" }
  metadata    = { owner = "sre" }
}

resource "hallpass_host_key" "h" {
  server_id  = hallpass_server.s.id
  public_key = %q
}

resource "hallpass_role" "deploy" {
  server_id          = hallpass_server.s.id
  alias              = "deploy"
  remote_user        = "deploy"
  capabilities       = [%s]
  default_duration   = "30m"
  max_duration       = %q
  approvals_required = 2
  enabled            = %t
}

resource "hallpass_login_key" "k" {
  role_id  = hallpass_role.deploy.id
  triggers = { rotation = %q }

  lifecycle {
    create_before_destroy = true
  }
}

resource "hallpass_login_key_activation" "k" {
  role_id      = hallpass_role.deploy.id
  login_key_id = hallpass_login_key.k.id
  depends_on   = [hallpass_host_key.h]
}

data "hallpass_server" "s" {
  alias      = hallpass_server.s.alias
  depends_on = [hallpass_server.s]
}

data "hallpass_role" "deploy" {
  server_id  = hallpass_server.s.id
  alias      = "deploy"
  depends_on = [hallpass_role.deploy]
}
`, alias, desc, acc.DestHost, acc.DestPort, acc.DestHostKey, caps, maxDur, roleEnabled, rotation)
	}
	var serverID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: resource.ComposeTestCheckFunc(
			checkGone(t, "hallpass_server", func(ctx context.Context, c *client.Client, a map[string]string) error {
				_, err := c.GetServer(ctx, a["id"])
				return err
			}),
			checkGone(t, "hallpass_role", func(ctx context.Context, c *client.Client, a map[string]string) error {
				_, err := c.GetRole(ctx, a["id"])
				return err
			}),
		),
		Steps: []resource.TestStep{
			{
				Config: cfg("Web front end", "240m", true, `"exec", "shell", "pty"`, "1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_server.s", "id", idRE("srv")),
					resource.TestCheckResourceAttr("hallpass_server.s", "display_name", alias),
					resource.TestCheckResourceAttr("hallpass_host_key.h", "algorithm", "ssh-ed25519"),
					resource.TestCheckResourceAttr("hallpass_role.deploy", "max_duration", "240m"),
					resource.TestCheckResourceAttr("hallpass_role.deploy", "recording_mode", "mandatory"),
					resource.TestCheckResourceAttr("hallpass_role.deploy", "approval_channels.#", "3"),
					resource.TestMatchResourceAttr("hallpass_login_key.k", "authorized_keys_line", regexp.MustCompile(`^restrict.* ssh-ed25519 .+ hallpass:`+alias+`/deploy$`)),
					resource.TestMatchResourceAttr("hallpass_login_key.k", "public_key", regexp.MustCompile(`^ssh-ed25519 \S+ hallpass:`+alias+`/deploy$`)),
					resource.TestCheckResourceAttr("hallpass_login_key_activation.k", "state", "active"),
					resource.TestCheckResourceAttrPair("data.hallpass_server.s", "id", "hallpass_server.s", "id"),
					resource.TestCheckResourceAttr("data.hallpass_server.s", "kind", "ssh"),
					resource.TestCheckResourceAttrPair("data.hallpass_role.deploy", "id", "hallpass_role.deploy", "id"),
					capture("hallpass_server.s", "id", &serverID),
				),
			},
			{
				// In-place updates, a capability set change, and disabling the role.
				Config:           cfg("Web front end (nginx)", "4h", false, `"exec", "file-transfer"`, "1"),
				ConfigPlanChecks: expectUpdate("hallpass_role.deploy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_server.s", "description", "Web front end (nginx)"),
					resource.TestCheckResourceAttr("hallpass_role.deploy", "max_duration", "4h"),
					resource.TestCheckResourceAttr("hallpass_role.deploy", "enabled", "false"),
					resource.TestCheckResourceAttr("hallpass_role.deploy", "capabilities.#", "2"),
				),
			},
			{
				// Rotation: a new key is generated, tested and activated before the old one is revoked.
				Config:           cfg("Web front end (nginx)", "4h", true, `"exec", "file-transfer"`, "2"),
				ConfigPlanChecks: expectReplace("hallpass_login_key.k"),
				Check:            resource.TestCheckResourceAttr("hallpass_login_key_activation.k", "state", "active"),
			},
			{ResourceName: "hallpass_server.s", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_role.deploy", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_host_key.h", ImportState: true, ImportStateIdFunc: importID("hallpass_host_key.h", "server_id", "id"),
				ImportStateVerify: true},
			// authorized_keys_line follows the role's capabilities (pty), so it changed with step 2 and is refreshed only on
			// the next read; the import reads the current value.
			{ResourceName: "hallpass_login_key.k", ImportState: true, ImportStateIdFunc: importID("hallpass_login_key.k", "role_id", "id"),
				ImportStateVerify: true, ImportStateVerifyIgnore: []string{"authorized_keys_line", "triggers"}},
			{
				// Out-of-band disable shows as drift and is undone.
				PreConfig: oob(t, func(ctx context.Context, c *client.Client) error {
					_, err := c.SetServerEnabled(ctx, serverID, false)
					return err
				}),
				Config:           cfg("Web front end (nginx)", "4h", false, `"exec", "file-transfer"`, "1"),
				ConfigPlanChecks: expectUpdate("hallpass_server.s"),
				Check:            resource.TestCheckResourceAttr("hallpass_server.s", "enabled", "true"),
			},
		},
	})
}
