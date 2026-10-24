resource "hallpass_git_access_profile" "acme_read" {
  server_id    = hallpass_git_remote.github.id
  alias        = "acme-read"
  repositories = ["acme/**"]
}

resource "hallpass_git_access_profile" "acme_push" {
  server_id          = hallpass_git_remote.github.id
  alias              = "acme-push"
  repositories       = ["acme/{api,web}"]
  allow_push         = true
  branches           = ["agent/**"]
  protected_branches = ["main", "release/*"]
  approvals_required = 2
}
