package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

func TestAccAgent(t *testing.T) {
	testAccPreCheck(t)
	name := randName("bot")
	key1, key2 := newPublicKey(t, "ci@runner"), newPublicKey(t, "ci@runner2")
	cfg := func(desc, cidrs string, enabled bool, key string) string {
		return fmt.Sprintf(`
resource "hallpass_agent" "a" {
  name         = %q
  description  = %q
  groups       = ["sre", "ci"]
  labels       = { team = "sre" }
  source_cidrs = [%s]
  enabled      = %t
}

resource "hallpass_agent_key" "k" {
  agent_id   = hallpass_agent.a.id
  public_key = %q
}
`, name, desc, cidrs, enabled, key)
	}
	var agentID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: checkGone(t, "hallpass_agent", func(ctx context.Context, c *client.Client, a map[string]string) error {
			_, err := c.GetAgent(ctx, a["id"])
			return err
		}),
		Steps: []resource.TestStep{
			{
				Config: cfg("CI runner", `"10.1.0.0/16"`, true, key1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("hallpass_agent.a", "id", idRE("agt")),
					resource.TestCheckResourceAttr("hallpass_agent.a", "groups.#", "2"),
					resource.TestCheckResourceAttr("hallpass_agent.a", "labels.team", "sre"),
					resource.TestCheckResourceAttr("hallpass_agent.a", "enabled", "true"),
					resource.TestMatchResourceAttr("hallpass_agent_key.k", "fingerprint", regexp.MustCompile(`^SHA256:`)),
					resource.TestCheckResourceAttr("hallpass_agent_key.k", "algorithm", "ssh-ed25519"),
					capture("hallpass_agent.a", "id", &agentID),
				),
			},
			{
				// Update in place, disable, and rotate the key (a new key replaces the old one).
				Config:           cfg("CI runner (paused)", "", false, key2),
				ConfigPlanChecks: expectUpdate("hallpass_agent.a"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_agent.a", "enabled", "false"),
					resource.TestCheckResourceAttr("hallpass_agent.a", "source_cidrs.#", "0"),
				),
			},
			{ResourceName: "hallpass_agent.a", ImportState: true, ImportStateVerify: true},
			{ResourceName: "hallpass_agent_key.k", ImportState: true, ImportStateIdFunc: importID("hallpass_agent_key.k", "agent_id", "id"),
				ImportStateVerify: true},
			{
				// Out-of-band deletion: the next plan recreates the agent.
				PreConfig:        oob(t, func(ctx context.Context, c *client.Client) error { return c.DeleteAgent(ctx, agentID) }),
				Config:           cfg("CI runner (paused)", "", false, newPublicKey(t, "ci@runner3")),
				ConfigPlanChecks: expectRecreate("hallpass_agent.a"),
			},
		},
	})
}
