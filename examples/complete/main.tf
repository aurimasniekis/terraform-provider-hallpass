# A complete HallPass setup: an SRE agent, a web server with read-only and deploy roles, a GitHub remote with read
# and push profiles, policy, approvers, and Slack approvals. scripts/verify-example.sh applies and destroys it against
# a throwaway HallPass (login keys are generated but not activated, since nothing is installed on real hosts).

terraform {
  required_providers {
    hallpass = {
      source = "aurimasniekis/hallpass"
    }
  }
}

provider "hallpass" {}

variable "agent_public_key" {
  type    = string
  default = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxCyW6nj/zJKxr3Lt+ydUMfvj+mU9LVkNvA9FZOJosn claude-sre@example"
}

resource "hallpass_agent" "claude_sre" {
  name        = "claude-sre"
  description = "Claude Code SRE assistant"
  groups      = ["sre-agents"]
}

resource "hallpass_agent_key" "claude_sre" {
  agent_id   = hallpass_agent.claude_sre.id
  public_key = var.agent_public_key
}

resource "hallpass_server" "web1" {
  alias       = "web1"
  description = "Public web front end (nginx)"
  environment = "production"
  address     = "127.0.0.1"
  port        = 2201
  groups      = ["prod-web"]
  labels      = { env = "prod", tier = "web" }
}

resource "hallpass_role" "inspect" {
  server_id    = hallpass_server.web1.id
  alias        = "inspect"
  remote_user  = "ro"
  description  = "Read logs and service status. No sudo."
  max_duration = "2h"
}

resource "hallpass_role" "deploy" {
  server_id          = hallpass_server.web1.id
  alias              = "deploy"
  remote_user        = "deploy"
  capabilities       = ["exec", "file-transfer"]
  approvals_required = 2
}

resource "hallpass_login_key" "inspect" {
  role_id = hallpass_role.inspect.id
}

resource "hallpass_git_remote" "github" {
  alias   = "github"
  address = "github.com"
}

resource "hallpass_host_key" "github" {
  server_id  = hallpass_git_remote.github.id
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
}

resource "hallpass_git_access_profile" "acme_push" {
  server_id          = hallpass_git_remote.github.id
  alias              = "acme-push"
  repositories       = ["acme/{api,web}"]
  allow_push         = true
  branches           = ["agent/**"]
  protected_branches = ["main"]
}

resource "hallpass_login_key" "acme_push" {
  role_id = hallpass_git_access_profile.acme_push.id
}

resource "hallpass_policy_rule" "inspect" {
  name              = "SRE inspect production"
  effect            = "allow"
  level             = "auto_approve"
  subjects          = { agent_groups = ["sre-agents"] }
  targets           = { server_labels = { match_labels = { env = "prod" } } }
  roles             = { names = ["inspect"] }
  auto_max_duration = "30m"
  require_reason    = false
}

resource "hallpass_policy_rule" "changes" {
  name     = "SRE changes and pushes on request"
  effect   = "allow"
  level    = "requestable"
  subjects = { agent_groups = ["sre-agents"] }
  targets  = { servers = [hallpass_server.web1.id, hallpass_git_remote.github.id] }
  roles    = { names = ["deploy", "acme-push"] }
}

resource "hallpass_approver_rule" "admins" {
  name      = "Administrators approve everything"
  operators = { all = true }
  targets   = { all = true }
  roles     = { all = true }
}

resource "hallpass_integration" "slack" {
  name  = "ops-approvals"
  slack = { team_id = "T0123456789" }
  secrets = {
    bot_token      = "xoxb-example"
    signing_secret = "example-signing-secret"
  }
}

resource "hallpass_notification_route" "prod" {
  integration_id = hallpass_integration.slack.id
  destination    = "C0123456789"
  targets        = { server_groups = ["prod-web"] }
}

output "web1_inspect_authorized_keys_line" {
  value = hallpass_login_key.inspect.authorized_keys_line
}

output "github_deploy_key" {
  value = hallpass_login_key.acme_push.public_key
}
