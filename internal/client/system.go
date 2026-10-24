package client

import "context"

// GatewayHostKey is a host key of the HallPass SSH gateway (for agents' known_hosts).
type GatewayHostKey struct {
	ID          string `json:"id"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
}

func (c *Client) ListGatewayHostKeys(ctx context.Context) ([]GatewayHostKey, error) {
	l, err := get[list[GatewayHostKey]](ctx, c, "/system/gateway-host-keys", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

// Operator is a person who signs in to the console.
type Operator struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Enabled     bool     `json:"enabled"`
	Roles       []string `json:"roles"`
	Groups      []string `json:"groups"`
}

func (c *Client) ListOperators(ctx context.Context) ([]Operator, error) {
	l, err := get[list[Operator]](ctx, c, "/operators", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

// Group is a named group of agents, servers or operators.
type Group struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	l, err := get[list[Group]](ctx, c, "/groups", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}
