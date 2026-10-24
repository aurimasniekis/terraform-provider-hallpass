resource "hallpass_role" "web1_inspect" {
  server_id        = hallpass_server.web1.id
  alias            = "inspect"
  description      = "Read logs and service status. No sudo."
  remote_user      = "ro"
  capabilities     = ["exec", "shell", "pty"]
  default_duration = "30m"
  max_duration     = "2h"
}

resource "hallpass_role" "web1_deploy" {
  server_id          = hallpass_server.web1.id
  alias              = "deploy"
  remote_user        = "deploy"
  capabilities       = ["exec", "file-transfer"]
  max_duration       = "4h"
  approvals_required = 2
  approval_channels  = ["web", "slack"]
}
