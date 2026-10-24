resource "hallpass_notification_route" "prod" {
  integration_id = hallpass_integration.slack.id
  destination    = "C0123456789"
  targets        = { server_labels = { match_labels = { env = "prod" } } }
}
