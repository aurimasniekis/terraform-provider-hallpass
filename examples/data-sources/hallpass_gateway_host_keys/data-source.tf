# Pin the gateway in agents' known_hosts (never trust it on first use).
data "hallpass_gateway_host_keys" "gw" {
  host = "hallpass.example.com"
  port = 2222
}

resource "local_file" "known_hosts" {
  filename = "${path.module}/known_hosts"
  content  = data.hallpass_gateway_host_keys.gw.known_hosts
}
