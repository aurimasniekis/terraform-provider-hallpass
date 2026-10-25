package client

import "context"

// JITRules restrict just-in-time provisioning.
type JITRules struct {
	EmailDomains  []string `json:"email_domains"`
	Tenants       []string `json:"tenants"`
	HostedDomains []string `json:"hosted_domains"`
	Groups        []string `json:"groups"`
}

// OIDCProvider is a single sign-on provider. The client secret is write-only.
type OIDCProvider struct {
	ID                        string    `json:"id"`
	Slug                      string    `json:"slug"`
	DisplayName               string    `json:"display_name"`
	Issuer                    string    `json:"issuer"`
	ClientID                  string    `json:"client_id"`
	HasClientSecret           bool      `json:"has_client_secret"`
	Scopes                    []string  `json:"scopes"`
	GroupsClaim               string    `json:"groups_claim"`
	Provisioning              string    `json:"provisioning"`
	JIT                       *JITRules `json:"jit"`
	AllowPrivateNetwork       bool      `json:"allow_private_network"`
	AllowCrossOriginEndpoints bool      `json:"allow_cross_origin_endpoints"`
	CABundlePEM               string    `json:"ca_bundle_pem"`
	StepUpFallback            string    `json:"stepup_fallback"`
	ACRValues                 []string  `json:"acr_values"`
	EndSessionEnabled         bool      `json:"end_session_enabled"`
	Enabled                   bool      `json:"enabled"`
	Version                   int64     `json:"version"`
	RedirectURI               string    `json:"redirect_uri"`
}

// CreateOIDCProvider creates a provider from the given fields (unset fields take HallPass's defaults).
func (c *Client) CreateOIDCProvider(ctx context.Context, body map[string]any) (*OIDCProvider, error) {
	return create[OIDCProvider](ctx, c, "/oidc-providers", body)
}

func (c *Client) GetOIDCProvider(ctx context.Context, id string) (*OIDCProvider, error) {
	return get[OIDCProvider](ctx, c, "/oidc-providers/"+esc(id), nil)
}

// UpdateOIDCProvider changes the given fields; client_secret left out keeps the stored secret.
func (c *Client) UpdateOIDCProvider(ctx context.Context, id string, version int64, body map[string]any) (*OIDCProvider, error) {
	body["version"] = version
	return patch[OIDCProvider](ctx, c, "/oidc-providers/"+esc(id), version, body)
}

func (c *Client) DeleteOIDCProvider(ctx context.Context, id string) error {
	return c.del(ctx, "/oidc-providers/"+esc(id))
}

// OIDCMapping maps a groups-claim value to an operator role or an operator group.
type OIDCMapping struct {
	ID         string `json:"id"`
	ProviderID string `json:"provider_id"`
	GroupValue string `json:"group_value"`
	Role       string `json:"role,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
}

func (c *Client) AddOIDCMapping(ctx context.Context, providerID, groupValue, role, groupID string) (*OIDCMapping, error) {
	body := map[string]string{"group_value": groupValue}
	if role != "" {
		body["role"] = role
	}
	if groupID != "" {
		body["group_id"] = groupID
	}
	return create[OIDCMapping](ctx, c, "/oidc-providers/"+esc(providerID)+"/mappings", body)
}

// GetOIDCMapping finds a mapping of a provider.
func (c *Client) GetOIDCMapping(ctx context.Context, providerID, id string) (*OIDCMapping, error) {
	l, err := get[list[OIDCMapping]](ctx, c, "/oidc-providers/"+esc(providerID)+"/mappings", nil)
	if err != nil {
		return nil, err
	}
	for _, m := range l.Items {
		if m.ID == id {
			return &m, nil
		}
	}
	return nil, notFound("/oidc-providers/"+providerID+"/mappings/"+id, "OIDC mapping")
}

func (c *Client) DeleteOIDCMapping(ctx context.Context, providerID, id string) error {
	return c.del(ctx, "/oidc-providers/"+esc(providerID)+"/mappings/"+esc(id))
}

// AuthSettings are installation-wide sign-in settings.
type AuthSettings struct {
	LocalLoginDisabled bool `json:"local_login_disabled"`
	// DirectProvider is the slug of the SSO provider the sign-in page goes to directly ("" for none). Omitted in a
	// request, HallPass leaves it unchanged (servers before 0.3.0 do not know the field).
	DirectProvider *string `json:"direct_provider,omitempty"`
}

func (c *Client) GetAuthSettings(ctx context.Context) (*AuthSettings, error) {
	return get[AuthSettings](ctx, c, "/settings/auth", nil)
}

func (c *Client) SetAuthSettings(ctx context.Context, in AuthSettings) (*AuthSettings, error) {
	return put[AuthSettings](ctx, c, "/settings/auth", in)
}
