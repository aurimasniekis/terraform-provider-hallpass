resource "hallpass_oidc_group_mapping" "admins" {
  provider_id = hallpass_oidc_provider.entra.id
  group_value = "22222222-2222-2222-2222-222222222222"
  role        = "administrator"
}
