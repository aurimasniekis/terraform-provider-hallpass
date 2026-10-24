data "hallpass_operator" "ada" {
  email = "ada@example.com"
}

resource "hallpass_approver_rule" "web" {
  name      = "Ada approves web changes"
  operators = { operators = [data.hallpass_operator.ada.id] }
  targets   = { server_groups = ["prod-web"] }
  roles     = { all = true }
}
