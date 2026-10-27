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

# Terraform 1.11+: a write-only secret, e.g. from an ephemeral resource, never stored in plan or state.
# Bump secret_wo_version to send a rotated secret.
resource "hallpass_api_credential" "cloudflare" {
  role_id           = hallpass_api_access_profile.cloudflare_dns.id
  type              = "bearer"
  secret_wo         = ephemeral.onepassword_item.cloudflare.credential
  secret_wo_version = 1
}
