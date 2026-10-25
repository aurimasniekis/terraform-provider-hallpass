package client

import (
	"context"
	"net/http"
)

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

// BackupTarget is the object storage target of scheduled backups (the secret is never returned).
type BackupTarget struct {
	Enabled             bool   `json:"enabled"`
	Endpoint            string `json:"endpoint"`
	Region              string `json:"region"`
	Bucket              string `json:"bucket"`
	Prefix              string `json:"prefix"`
	PathStyle           bool   `json:"path_style"`
	AccessKeyID         string `json:"access_key_id"`
	CABundlePEM         string `json:"ca_bundle_pem,omitempty"`
	AllowPrivateNetwork bool   `json:"allow_private_network"`
	Interval            string `json:"interval"`
	KeepLast            int64  `json:"keep_last"`
	KeepDailyDays       int64  `json:"keep_daily_days"`
	Version             int64  `json:"version"`
}

// BackupTargetInput creates or replaces the target. SecretAccessKey is omitted to keep the stored one.
type BackupTargetInput struct {
	Enabled             bool    `json:"enabled"`
	Endpoint            string  `json:"endpoint"`
	Region              string  `json:"region"`
	Bucket              string  `json:"bucket"`
	Prefix              string  `json:"prefix"`
	PathStyle           bool    `json:"path_style"`
	AccessKeyID         string  `json:"access_key_id"`
	SecretAccessKey     *string `json:"secret_access_key,omitempty"`
	CABundlePEM         string  `json:"ca_bundle_pem"`
	AllowPrivateNetwork bool    `json:"allow_private_network"`
	Interval            string  `json:"interval"`
	KeepLast            int64   `json:"keep_last"`
	KeepDailyDays       int64   `json:"keep_daily_days"`
}

func (c *Client) GetBackupTarget(ctx context.Context) (*BackupTarget, error) {
	return get[BackupTarget](ctx, c, "/system/backups/target", nil)
}

// PutBackupTarget creates the target (version 0) or replaces it (If-Match version).
func (c *Client) PutBackupTarget(ctx context.Context, version int64, in BackupTargetInput) (*BackupTarget, error) {
	return call[BackupTarget](ctx, c, &request{method: http.MethodPut, path: "/system/backups/target", body: in, version: version})
}

func (c *Client) DeleteBackupTarget(ctx context.Context) error {
	return c.del(ctx, "/system/backups/target")
}
