resource "hallpass_login_key" "web1_inspect" {
  role_id  = hallpass_role.web1_inspect.id
  triggers = { rotation = "2026-10" } # change to rotate

  lifecycle {
    create_before_destroy = true
  }
}

# Install authorized_keys_line on the server with your configuration management, for example:
output "web1_inspect_authorized_keys_line" {
  value = hallpass_login_key.web1_inspect.authorized_keys_line
}

# A git access profile's key goes to the git host, e.g. as a GitHub deploy key.
resource "hallpass_login_key" "acme_push" {
  role_id = hallpass_git_access_profile.acme_push.id
}

resource "github_repository_deploy_key" "api" {
  repository = "api"
  title      = "HallPass acme-push"
  key        = hallpass_login_key.acme_push.public_key
  read_only  = false
}
