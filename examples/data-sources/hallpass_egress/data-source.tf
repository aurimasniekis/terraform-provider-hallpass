# Allow SSH on destinations only from the gateway.
data "hallpass_egress" "gw" {}

output "gateway_source_addresses" {
  value = data.hallpass_egress.gw.source_addresses
}
