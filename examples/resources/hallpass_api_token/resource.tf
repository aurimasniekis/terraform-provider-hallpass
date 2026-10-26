# A read-only token for an integration, issued by the provider's Administrator token and stored in a secret manager.
resource "hallpass_api_token" "deed" {
  name          = "deed-connector"
  role          = "auditor"
  never_expires = true

  # Change the value to rotate; the old token stays valid until the new one is stored.
  triggers = { rotation = "2026-10" }

  lifecycle {
    create_before_destroy = true
  }
}

# A short-lived token for a report job.
resource "hallpass_api_token" "weekly_report" {
  name            = "weekly-report"
  role            = "viewer"
  expires_in_days = 90
}

output "deed_token" {
  value     = hallpass_api_token.deed.token
  sensitive = true
}
