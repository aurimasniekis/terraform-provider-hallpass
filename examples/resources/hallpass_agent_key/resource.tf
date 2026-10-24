resource "hallpass_agent_key" "claude_sre" {
  agent_id   = hallpass_agent.claude_sre.id
  public_key = file("~/.ssh/claude_sre_ed25519.pub")
}
