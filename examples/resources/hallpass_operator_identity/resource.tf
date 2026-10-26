# Ada signs in with the company IdP; the subject is the IdP's `sub` claim for her account.
resource "hallpass_operator_identity" "ada" {
  operator_id = hallpass_operator.ada.id
  provider_id = hallpass_oidc_provider.company.id
  subject     = "00u1a2b3c4d5e6f7g8h9"
}
