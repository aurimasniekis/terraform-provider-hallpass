# Terraform provider for HallPass

Manage a [HallPass](https://github.com/aurimasniekis/go-hallpass) gateway (a terminating SSH gateway for AI agents) as
code: agents and their keys, servers and git remotes, roles and git access profiles, pinned host keys, login keys,
policy and approver rules, single sign-on, chat approvals and installation settings.

Built with [terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework) (protocol 6). Needs
HallPass 0.1.0 or later (`hallpass_backup_target` needs 0.2.0, `direct_provider` on `hallpass_auth_settings` needs 0.3.0, and the operator, API token, destination collector and egress resources need 0.5.0). Tested against a real HallPass started by the acceptance tests, with Terraform 1.11.

## Usage

```hcl
terraform {
  required_providers {
    hallpass = {
      source  = "aurimasniekis/hallpass"
      version = "~> 0.1"
    }
  }
}

provider "hallpass" {
  endpoint = "https://hallpass.example.com" # or HALLPASS_ENDPOINT
  token    = var.hallpass_token             # or HALLPASS_TOKEN
  # ca_file = "/etc/ssl/private-ca.pem"      # or HALLPASS_CA_FILE
}
```

The provider authenticates with a HallPass **API token** (`hallpass_at_…`). An administrator creates one under
**Administration → API tokens** (it needs a recent sign-in with MFA). A token:

- acts for the administrator who created it, with one role (use **Administrator** for Terraform);
- stops working when it expires (1-366 days, or never if issued with **Never expires**), is revoked, or its creator is
  disabled or loses the role;
- can read and change configuration, and with the Administrator role manage operators and issue tokens of its own
  (`hallpass_operator`, `hallpass_api_token`). Approving requests, reading recordings, invitations and lockdown always
  need a person in the console.

Every change Terraform makes is in the HallPass audit log under the token creator's name, marked with the token.

See [`examples/`](examples) for one example per resource and [`examples/complete`](examples/complete/main.tf) for a
whole setup: an agent, a server with read-only and deploy roles, a GitHub remote with read and push profiles, policy,
approvers and Slack approvals.

### Resources and data sources

| Resource | What it is | Import ID |
|---|---|---|
| `hallpass_agent` | An AI agent identity | `<agent_id>` |
| `hallpass_agent_key` | A public key the agent signs in with | `<agent_id>/<key_id>` |
| `hallpass_server` | A destination server | `<server_id>` |
| `hallpass_git_remote` | A git host (GitHub, GitLab, your own) | `<server_id>` |
| `hallpass_host_key` | A pinned host key of a server or git remote | `<server_id>/<host_key_id>` |
| `hallpass_role` | A role on a server: remote account, capabilities, limits | `<role_id>` |
| `hallpass_git_access_profile` | Repositories and push rules on a git remote | `<role_id>` |
| `hallpass_login_key` | A login key HallPass generates for a role or profile | `<role_id>/<login_key_id>` |
| `hallpass_login_key_activation` | Test-logs-in with a login key, then activates it | — |
| `hallpass_policy_rule` | Who may see, request or auto-approve what | `<rule_id>` |
| `hallpass_approver_rule` | Who may approve which requests | `<rule_id>` |
| `hallpass_oidc_provider` | A single sign-on provider for the console | `<provider_id>` |
| `hallpass_oidc_group_mapping` | An SSO group mapped to an operator role or group | `<provider_id>/<mapping_id>` |
| `hallpass_integration` | A Slack or Telegram approval integration | `<integration_id>` |
| `hallpass_notification_route` | Where approval requests for which servers go | `<route_id>` |
| `hallpass_self_approval` | Whether agent owners may approve their own agents | — |
| `hallpass_auth_settings` | Whether password sign-in is turned off | — |
| `hallpass_backup_target` | Scheduled, encrypted backups to S3-compatible storage | `backup-target` |
| `hallpass_destination_collector` | A destination audit collector's key on one server | `<collector_id>` |
| `hallpass_operator` | A person who signs in to the console, with roles and groups | `<operator_id>` |
| `hallpass_operator_identity` | A single sign-on identity linked to an operator | `<operator_id>/<provider_id>/<subject>` |
| `hallpass_operator_chat_link` | A Slack or Telegram account an operator approves from | `<operator_id>/<platform>/<workspace>/<user_id>` |
| `hallpass_api_token` | An API token for an integration, e.g. read-only Auditor | — |

Data sources: `hallpass_server`, `hallpass_agent`, `hallpass_role`, `hallpass_operator` (find an operator by email,
for approver rules), `hallpass_gateway_host_keys` (the gateway's host keys and `known_hosts` lines for agents) and
`hallpass_egress` (the gateway's egress ranges and source addresses from its configuration file).

### Things to know

- **Login keys are installed outside HallPass.** `hallpass_login_key` generates the key; install its
  `authorized_keys_line` on the server (or its `public_key` as a deploy key on the git host), then
  `hallpass_login_key_activation` test-logs-in and activates it. Rotate by changing `triggers` with
  `create_before_destroy`:

  ```hcl
  resource "hallpass_login_key" "acme_push" {
    role_id = hallpass_git_access_profile.acme_push.id
  }

  resource "github_repository_deploy_key" "api" {
    repository = "api"
    title      = "HallPass acme-push"
    key        = hallpass_login_key.acme_push.public_key
    read_only  = false
  }

  resource "hallpass_login_key_activation" "acme_push" {
    role_id      = hallpass_git_access_profile.acme_push.id
    login_key_id = hallpass_login_key.acme_push.id
    depends_on   = [github_repository_deploy_key.api, hallpass_host_key.github]
  }
  ```

- **Host keys are trusted when created.** Take them from your provisioning or the provider's published keys, never
  from an unverified scan.
- **Revoked agent keys are gone for good.** HallPass never accepts a revoked key again, on any agent, so rotate agent
  keys by adding the new key before removing the old one.
- **Deleting keeps history.** Destroying an agent, server, git remote, role or profile deletes it in HallPass: access
  ends and its keys are revoked, and the name can be reused. Past sessions and the audit log still show it.
- **The provider's token is powerful.** With operators and identities in Terraform, whoever holds the Administrator
  token can create an approver account and link their own SSO identity or chat account to it. Keep it in a secret
  manager and give integrations their own lower-role `hallpass_api_token`.
- **Operators are disabled, not deleted.** Destroying a `hallpass_operator` disables it and removes its manual roles;
  the provider's token cannot change the operator it acts for. `hallpass_api_token` values exist only in state, so
  write them to your secret manager in the same configuration.
- **Egress stays in the configuration file.** `egress.allow_cidrs` guards against servers being pointed at internal
  addresses, so Terraform only reads it (`hallpass_egress`). Set it to the subnets your servers live in.
- **Durations** are written as `30m`, `4h` or `1h30m`.
- **Disabling** (`enabled = false`) ends active access within seconds and cancels pending requests; set it back to
  `true` to let policy decide again.

## Development

```sh
make build       # bin/terraform-provider-hallpass
make test        # unit tests
make testacc     # acceptance tests: exports ../hallpass at HALLPASS_COMMIT, builds it, starts it, runs every resource
make example     # applies and destroys examples/complete against a throwaway HallPass
make lint docs   # golangci-lint; regenerate docs/ with tfplugindocs
```

The acceptance tests start `hallpass serve` in development mode on free loopback ports, complete the first
administrator's sign-in with TOTP, issue an API token, and run a small SSH server on loopback that stands in for
servers and git hosts so login keys can be tested and activated. Nothing reaches the network.

## License

Apache-2.0, see [LICENSE](LICENSE).
