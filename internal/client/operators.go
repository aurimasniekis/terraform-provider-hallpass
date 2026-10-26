package client

import (
	"context"
	"net/http"
	"net/url"
)

// OperatorDetail is an operator with the source of each role (manual roles are the ones Terraform manages).
type OperatorDetail struct {
	Operator
	RoleAssignments []RoleAssignment `json:"role_assignments"`
	HasPassword     bool             `json:"has_password"`
	Version         int64            `json:"version"`
}

// RoleAssignment is one role of an operator: "manual", or "sso" when mapped from a single sign-on group.
type RoleAssignment struct {
	Role      string `json:"role"`
	Source    string `json:"source"`
	SourceRef string `json:"source_ref,omitempty"`
}

// ManualRoles returns the roles assigned by an administrator (not mapped from single sign-on).
func (o *OperatorDetail) ManualRoles() []string {
	out := []string{}
	for _, a := range o.RoleAssignments {
		if a.Source == "manual" {
			out = append(out, a.Role)
		}
	}
	return out
}

// OperatorCreate creates an operator. It has no password: the person signs in with single sign-on, or an
// administrator sends a password-reset link from the console.
type OperatorCreate struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
}

// OperatorPatch changes an operator; nil fields stay unchanged.
type OperatorPatch struct {
	Roles   *[]string `json:"roles,omitempty"`
	Groups  *[]string `json:"groups,omitempty"`
	Enabled *bool     `json:"enabled,omitempty"`
}

func (c *Client) CreateOperator(ctx context.Context, in OperatorCreate) (*OperatorDetail, error) {
	return create[OperatorDetail](ctx, c, "/operators", in)
}

func (c *Client) GetOperator(ctx context.Context, id string) (*OperatorDetail, error) {
	return get[OperatorDetail](ctx, c, "/operators/"+esc(id), nil)
}

func (c *Client) UpdateOperator(ctx context.Context, id string, in OperatorPatch) (*OperatorDetail, error) {
	return patch[OperatorDetail](ctx, c, "/operators/"+esc(id), 0, in)
}

// OperatorIdentity is a single sign-on identity linked to an operator.
type OperatorIdentity struct {
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	ProviderID string `json:"provider_id"`
	OperatorID string `json:"operator_id"`
	LinkedVia  string `json:"linked_via"`
}

func (c *Client) ListOperatorIdentities(ctx context.Context, operatorID string) ([]OperatorIdentity, error) {
	l, err := get[list[OperatorIdentity]](ctx, c, "/operators/"+esc(operatorID)+"/identities", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (c *Client) LinkOperatorIdentity(ctx context.Context, operatorID, providerID, subject string) error {
	_, err := post[struct{}](ctx, c, "/operators/"+esc(operatorID)+"/identities", map[string]string{"provider_id": providerID, "subject": subject})
	return err
}

func (c *Client) UnlinkOperatorIdentity(ctx context.Context, operatorID, issuer, subject string) error {
	_, err := c.do(ctx, &request{method: http.MethodDelete, path: "/operators/" + esc(operatorID) + "/identities",
		query: url.Values{"issuer": {issuer}, "subject": {subject}}})
	return err
}

// ChatLink links a Slack or Telegram account to an operator, so its approvals act as that operator.
type ChatLink struct {
	Provider       string `json:"provider"`
	Workspace      string `json:"workspace"`
	ProviderUserID string `json:"provider_user_id"`
	OperatorID     string `json:"operator_id,omitempty"`
	Display        string `json:"display,omitempty"`
	LinkedVia      string `json:"linked_via,omitempty"`
}

func (c *Client) ListChatLinks(ctx context.Context, operatorID string) ([]ChatLink, error) {
	l, err := get[list[ChatLink]](ctx, c, "/operators/"+esc(operatorID)+"/provider-links", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (c *Client) LinkChat(ctx context.Context, operatorID string, in ChatLink) error {
	_, err := post[struct{}](ctx, c, "/operators/"+esc(operatorID)+"/provider-links", in)
	return err
}

func (c *Client) UnlinkChat(ctx context.Context, operatorID, provider, workspace, userID string) error {
	_, err := c.do(ctx, &request{method: http.MethodDelete, path: "/operators/" + esc(operatorID) + "/provider-links",
		query: url.Values{"provider": {provider}, "workspace": {workspace}, "user_id": {userID}}})
	return err
}

// APIToken describes an API token (never the token itself).
type APIToken struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	OperatorID    string `json:"operator_id"`
	Role          string `json:"role"`
	Hint          string `json:"hint"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	NeverExpires  bool   `json:"never_expires"`
	LastUsedAt    string `json:"last_used_at,omitempty"`
	RevokedAt     string `json:"revoked_at,omitempty"`
	ParentTokenID string `json:"parent_token_id,omitempty"`
}

// APITokenInput issues a token: either ExpiresInDays (1-366) or NeverExpires.
type APITokenInput struct {
	Name          string `json:"name"`
	Role          string `json:"role"`
	ExpiresInDays int64  `json:"expires_in_days,omitempty"`
	NeverExpires  bool   `json:"never_expires,omitempty"`
}

// APITokenCreated carries the token, which HallPass returns only here.
type APITokenCreated struct {
	Token    string   `json:"token"`
	APIToken APIToken `json:"api_token"`
}

func (c *Client) CreateAPIToken(ctx context.Context, in APITokenInput) (*APITokenCreated, error) {
	return create[APITokenCreated](ctx, c, "/api-tokens", in)
}

func (c *Client) GetAPIToken(ctx context.Context, id string) (*APIToken, error) {
	return get[APIToken](ctx, c, "/api-tokens/"+esc(id), nil)
}

func (c *Client) RevokeAPIToken(ctx context.Context, id string) error {
	return c.del(ctx, "/api-tokens/"+esc(id))
}

// DestinationCollector is a destination audit collector's enrolled key for one server.
type DestinationCollector struct {
	ID          string `json:"id"`
	ServerID    string `json:"server_id"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
	CreatedAt   string `json:"created_at"`
}

// DestinationCollectorInput enrolls a collector.
type DestinationCollectorInput struct {
	ServerID  string `json:"server_id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func (c *Client) RegisterDestinationCollector(ctx context.Context, in DestinationCollectorInput) (*DestinationCollector, error) {
	return create[DestinationCollector](ctx, c, "/destination-collectors", in)
}

func (c *Client) GetDestinationCollector(ctx context.Context, id string) (*DestinationCollector, error) {
	return get[DestinationCollector](ctx, c, "/destination-collectors/"+esc(id), nil)
}

func (c *Client) RevokeDestinationCollector(ctx context.Context, id, reason string) error {
	_, err := call[DestinationCollector](ctx, c, &request{method: http.MethodPost, path: "/destination-collectors/" + esc(id) + "/revoke",
		body: map[string]string{"reason": reason}, create: true})
	return err
}

// Egress is the gateway's egress configuration from its config file (read-only).
type Egress struct {
	AllowCIDRs        []string `json:"allow_cidrs"`
	AllowSpecialCIDRs []string `json:"allow_special_cidrs"`
	SourceAddresses   []string `json:"source_addresses"`
}

func (c *Client) GetEgress(ctx context.Context) (*Egress, error) {
	return get[Egress](ctx, c, "/system/egress", nil)
}
