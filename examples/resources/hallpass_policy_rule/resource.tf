resource "hallpass_policy_rule" "sre_inspect" {
  name     = "SRE inspect production"
  effect   = "allow"
  level    = "auto_approve"
  subjects = { agent_groups = ["sre-agents"] }
  targets  = { server_labels = { match_labels = { env = "prod" } } }
  roles    = { names = ["inspect"] }

  auto_max_duration = "30m"
  max_duration      = "2h"
  require_reason    = false
}

resource "hallpass_policy_rule" "sre_changes" {
  name     = "SRE changes on request"
  effect   = "allow"
  level    = "requestable"
  subjects = { agent_groups = ["sre-agents"] }
  targets  = { server_groups = ["prod-web"] }
  roles    = { names = ["deploy"] }
}

resource "hallpass_policy_rule" "no_bots_on_db" {
  name     = "Release bot never reaches databases"
  effect   = "deny"
  subjects = { agents = [hallpass_agent.claude_sre.id] }
  targets  = { server_labels = { match_labels = { tier = "db" } } }
  roles    = { all = true }
}
