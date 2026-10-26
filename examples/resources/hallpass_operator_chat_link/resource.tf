# Ada approves from Telegram: her numeric Telegram user ID, and the bot's workspace identifier as the console shows it.
resource "hallpass_operator_chat_link" "ada_telegram" {
  operator_id      = hallpass_operator.ada.id
  platform         = "telegram"
  workspace        = "7012345678"
  provider_user_id = "123456789"
  display          = "@ada"
}
