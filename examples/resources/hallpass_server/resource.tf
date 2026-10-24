resource "hallpass_server" "web1" {
  alias       = "web1"
  description = "Public web front end (nginx)"
  environment = "production"
  address     = "10.0.1.11"
  groups      = ["prod-web"]
  labels      = { env = "prod", tier = "web" }
}
