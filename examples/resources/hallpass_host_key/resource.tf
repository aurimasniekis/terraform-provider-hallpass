# The key must come from a trusted source: your provisioning, or the provider's published keys.
resource "hallpass_host_key" "web1" {
  server_id  = hallpass_server.web1.id
  public_key = file("${path.module}/keys/web1_ssh_host_ed25519_key.pub")
}

# GitHub's published Ed25519 host key.
resource "hallpass_host_key" "github" {
  server_id  = hallpass_git_remote.github.id
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
}
