# Only after an administrator completed a single sign-on test login in the console.
resource "hallpass_auth_settings" "this" {
  local_login_disabled = true
}
