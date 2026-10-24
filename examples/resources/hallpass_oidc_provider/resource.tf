resource "hallpass_oidc_provider" "entra" {
  slug          = "entra"
  display_name  = "Microsoft Entra ID"
  issuer        = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
  client_id     = "11111111-1111-1111-1111-111111111111"
  client_secret = var.entra_client_secret
  groups_claim  = "groups"
  provisioning  = "jit"
  jit = {
    tenants = ["00000000-0000-0000-0000-000000000000"]
  }
}

output "entra_redirect_uri" {
  value = hallpass_oidc_provider.entra.redirect_uri
}
