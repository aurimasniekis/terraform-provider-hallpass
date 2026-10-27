package client

import "context"

// APITarget lists the HTTPS hosts of an API target (a server of kind "api").
type APITarget struct {
	Hosts []string `json:"hosts"`
}

// APIRules say which requests an API access profile allows.
type APIRules struct {
	Rules []APIRule `json:"rules"`
}

// APIRule allows or denies requests by method, host, path and GraphQL operation type; empty lists match anything.
type APIRule struct {
	Effect  string   `json:"effect"`
	Methods []string `json:"methods,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	GraphQL []string `json:"graphql,omitempty"`
}

// APICredential describes an API access profile's credential (never the secret).
type APICredential struct {
	RoleID    string   `json:"role_id"`
	Type      string   `json:"type"`
	Header    string   `json:"header"`
	Username  string   `json:"username"`
	Scopes    []string `json:"scopes"`
	Hint      string   `json:"hint"`
	Version   int64    `json:"version"`
	UpdatedAt string   `json:"updated_at"`
}

// APICredentialInput sets an API access profile's credential.
type APICredentialInput struct {
	Type     string   `json:"type"`
	Header   string   `json:"header,omitempty"`
	Username string   `json:"username,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Secret   string   `json:"secret"`
}

// APITargetCA is an API target's interception CA.
type APITargetCA struct {
	Certificate  string   `json:"certificate"`
	Fingerprint  string   `json:"fingerprint"`
	PermittedDNS []string `json:"permitted_dns"`
	NotAfter     string   `json:"not_after"`
}

func (c *Client) GetAPICredential(ctx context.Context, roleID string) (*APICredential, error) {
	return get[APICredential](ctx, c, "/roles/"+esc(roleID)+"/api-credential", nil)
}

func (c *Client) SetAPICredential(ctx context.Context, roleID string, in APICredentialInput) (*APICredential, error) {
	return put[APICredential](ctx, c, "/roles/"+esc(roleID)+"/api-credential", in)
}

func (c *Client) DeleteAPICredential(ctx context.Context, roleID string) error {
	return c.del(ctx, "/roles/"+esc(roleID)+"/api-credential")
}

func (c *Client) GetAPITargetCA(ctx context.Context, serverID string) (*APITargetCA, error) {
	return get[APITargetCA](ctx, c, "/servers/"+esc(serverID)+"/api-ca", nil)
}
