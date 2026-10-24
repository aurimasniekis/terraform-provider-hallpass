resource "hallpass_agent" "claude_sre" {
  name         = "claude-sre"
  description  = "Claude Code SRE assistant"
  groups       = ["sre-agents"]
  labels       = { team = "sre" }
  source_cidrs = ["10.20.0.0/16"]
}
