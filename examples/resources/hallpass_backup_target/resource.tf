# Hourly encrypted backups to an S3 bucket, keeping the newest 48 and one per day for 30 days.
resource "hallpass_backup_target" "s3" {
  endpoint          = "https://s3.eu-central-1.amazonaws.com"
  region            = "eu-central-1"
  bucket            = "acme-hallpass-backups"
  prefix            = "hallpass/"
  access_key_id     = var.backup_access_key_id
  secret_access_key = var.backup_secret_access_key
}

# Cloudflare R2:
#   endpoint = "https://<account-id>.r2.cloudflarestorage.com"
#   region   = "auto"

variable "backup_access_key_id" {
  type = string
}

variable "backup_secret_access_key" {
  type      = string
  sensitive = true
}
