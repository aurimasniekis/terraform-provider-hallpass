resource "hallpass_api_target" "github" {
  alias       = "github"
  description = "GitHub REST and GraphQL APIs"
  hosts       = ["api.github.com", "uploads.github.com"]
}

resource "hallpass_api_target" "gcp" {
  alias = "gcp"
  hosts = ["*.googleapis.com"]
}
