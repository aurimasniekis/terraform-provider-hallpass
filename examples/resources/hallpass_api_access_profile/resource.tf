# Reads, and GraphQL queries (gh uses GraphQL for most commands).
resource "hallpass_api_access_profile" "read" {
  server_id = hallpass_api_target.github.id
  alias     = "read"
  rules = [
    { effect = "allow", methods = ["GET", "HEAD"] },
    { effect = "allow", methods = ["POST"], paths = ["/graphql"], graphql = ["query"] },
    { effect = "deny", paths = ["/user/keys", "/user/keys/**", "/authorizations/**"] },
  ]
}

# Comments and labels on acme's issues, approved by a person each time.
resource "hallpass_api_access_profile" "issues" {
  server_id = hallpass_api_target.github.id
  alias     = "issues"
  rules = [
    { effect = "allow", methods = ["POST"], paths = ["/repos/acme/*/issues/*/comments", "/repos/acme/*/issues/*/labels"] },
  ]
  max_duration = "1h"
}
