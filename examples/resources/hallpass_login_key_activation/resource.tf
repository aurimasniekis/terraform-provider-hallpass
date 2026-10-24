# Activate once the key is installed: HallPass test-logs-in first and refuses to activate a key that does not work.
resource "hallpass_login_key_activation" "acme_push" {
  role_id      = hallpass_git_access_profile.acme_push.id
  login_key_id = hallpass_login_key.acme_push.id
  depends_on   = [github_repository_deploy_key.api, hallpass_host_key.github]
}
