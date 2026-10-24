data "hallpass_role" "web1_inspect" {
  server_id = data.hallpass_server.web1.id
  alias     = "inspect"
}
