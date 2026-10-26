# Signs in with the company SSO (see hallpass_operator_identity) and approves requests for the on-call group.
resource "hallpass_operator" "ada" {
  email        = "ada@example.com"
  display_name = "Ada Lovelace"
  roles        = ["approver", "viewer"]
  groups       = ["oncall"]
}
