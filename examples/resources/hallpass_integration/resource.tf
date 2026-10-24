resource "hallpass_integration" "slack" {
  name = "ops-approvals"
  slack = {
    team_id = "T0123456789"
  }
  secrets = {
    bot_token      = var.slack_bot_token
    signing_secret = var.slack_signing_secret
  }
}

resource "hallpass_integration" "telegram" {
  name = "on-call"
  telegram = {
    bot_username = "acme_hallpass_bot"
  }
  secrets = {
    bot_token = var.telegram_bot_token
  }
}
