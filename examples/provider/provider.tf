terraform {
  required_providers {
    hallpass = {
      source  = "aurimasniekis/hallpass"
      version = "~> 0.1"
    }
  }
}

provider "hallpass" {
  endpoint = "https://hallpass.example.com" # or HALLPASS_ENDPOINT
  token    = var.hallpass_token             # or HALLPASS_TOKEN (Administration → API tokens)
  # ca_file = "/etc/ssl/private-ca.pem"      # or HALLPASS_CA_FILE
}

variable "hallpass_token" {
  type      = string
  sensitive = true
}
