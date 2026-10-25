# Changelog

All notable changes to the HallPass Terraform provider are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, resources and attributes may change between minor versions.

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

[0.1.0]: https://github.com/aurimasniekis/terraform-provider-hallpass/releases/tag/v0.1.0
