# Changelog

All notable changes to the HallPass Terraform provider are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, resources and attributes may change between minor versions.

## [Unreleased]

## [0.4.0] - 2026-10-26

For [HallPass 0.5.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.5.0); the new resources need it.

### Added

- `hallpass_api_token`: an API token issued by the provider's Administrator token, for any role (for example a
  read-only Auditor token for an integration). The token is exported once (sensitive), rotated with `triggers`, issued
  again when revoked or expired outside Terraform, and revoked on destroy.
- `hallpass_operator`: operators with manual roles, operator groups and enabled state. Destroying disables the
  operator.
- `hallpass_operator_identity`: link a single sign-on identity (issuer and subject) to an operator.
- `hallpass_operator_chat_link`: link a Slack or Telegram account to an operator for chat approvals.
- `hallpass_destination_collector`: enroll a destination audit collector's key on a server, by server ID and public
  key.
- `hallpass_egress` data source: the gateway's egress ranges and source addresses (read-only).

## [0.3.0] - 2026-10-26

For [HallPass 0.3.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.3.0); `direct_provider` needs it.

### Added

- `hallpass_auth_settings.direct_provider`: send the sign-in page straight to one single sign-on provider, with
  `/login/password` as the fallback.

## [0.2.0] - 2026-10-25

For [HallPass 0.2.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.2.0); `hallpass_backup_target` needs it.

### Added

- `hallpass_backup_target`: scheduled, encrypted backups to S3-compatible object storage, with schedule and retention.

## [0.1.0] - 2026-10-25

First release, for [HallPass 0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0).

### Added

- Provider configuration with an API token (`endpoint`, `token`, `ca_file`, or `HALLPASS_ENDPOINT`,
  `HALLPASS_TOKEN`, `HALLPASS_CA_FILE`).
- Resources: `hallpass_agent`, `hallpass_agent_key`, `hallpass_server`, `hallpass_git_remote`, `hallpass_host_key`,
  `hallpass_role`, `hallpass_git_access_profile`, `hallpass_login_key`, `hallpass_login_key_activation`,
  `hallpass_policy_rule`, `hallpass_approver_rule`, `hallpass_self_approval`, `hallpass_auth_settings`,
  `hallpass_oidc_provider`, `hallpass_oidc_group_mapping`, `hallpass_integration` and
  `hallpass_notification_route`, all importable.
- Data sources: `hallpass_server`, `hallpass_agent`, `hallpass_role`, `hallpass_operator` and
  `hallpass_gateway_host_keys`.
- Optimistic concurrency on every update (`If-Match`), and retried creates that never duplicate (`Idempotency-Key`).

[0.4.0]: https://github.com/aurimasniekis/terraform-provider-hallpass/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aurimasniekis/terraform-provider-hallpass/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aurimasniekis/terraform-provider-hallpass/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/aurimasniekis/terraform-provider-hallpass/releases/tag/v0.1.0
