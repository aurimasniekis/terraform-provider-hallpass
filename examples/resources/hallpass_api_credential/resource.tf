resource "hallpass_api_credential" "github_read" {
  role_id = hallpass_api_access_profile.read.id
  type    = "bearer"
  secret  = var.github_read_token # a fine-grained token with read-only permissions
}

resource "hallpass_api_credential" "gcp" {
  role_id = hallpass_api_access_profile.gcp_read.id
  type    = "google_service_account"
  secret  = file("gcp-viewer-key.json")
}
