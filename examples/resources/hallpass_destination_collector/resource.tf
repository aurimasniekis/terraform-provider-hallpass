# The key printed by `hallpass-collector pubkey` on web1.
resource "hallpass_destination_collector" "web1" {
  server_id  = hallpass_server.web1.id
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq7cO0yVdHqfEyA3BqU0sNbB9p8l3zTt0hZfMq4kVqJ web1"
}
