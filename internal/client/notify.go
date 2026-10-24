package client

import "context"

// Integration is a Slack or Telegram approval integration. Secret values are write-only.
type Integration struct {
	ID          string         `json:"id"`
	Provider    string         `json:"provider"`
	Name        string         `json:"name"`
	Config      map[string]any `json:"config"`
	SecretsSet  []string       `json:"secrets_set"`
	Enabled     bool           `json:"enabled"`
	Version     int64          `json:"version"`
	WebhookPath string         `json:"webhook_path"`
}

// IntegrationInput creates or updates an integration. Secrets left out keep their stored values.
type IntegrationInput struct {
	Version  int64             `json:"version,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Name     string            `json:"name"`
	Config   map[string]any    `json:"config"`
	Secrets  map[string]string `json:"secrets,omitempty"`
	Enabled  bool              `json:"enabled"`
}

func (c *Client) CreateIntegration(ctx context.Context, in IntegrationInput) (*Integration, error) {
	in.Version = 0
	return create[Integration](ctx, c, "/integrations", in)
}

func (c *Client) GetIntegration(ctx context.Context, id string) (*Integration, error) {
	return get[Integration](ctx, c, "/integrations/"+esc(id), nil)
}

func (c *Client) UpdateIntegration(ctx context.Context, id string, version int64, in IntegrationInput) (*Integration, error) {
	in.Provider, in.Version = "", version
	return patch[Integration](ctx, c, "/integrations/"+esc(id), version, in)
}

func (c *Client) DeleteIntegration(ctx context.Context, id string) error {
	return c.del(ctx, "/integrations/"+esc(id))
}

// NotificationRoute sends approval requests for matching targets to a chat destination.
type NotificationRoute struct {
	ID            string         `json:"id"`
	IntegrationID string         `json:"integration_id"`
	Provider      string         `json:"provider"`
	Destination   string         `json:"destination"`
	Targets       TargetSelector `json:"targets"`
	Enabled       bool           `json:"enabled"`
}

func (c *Client) CreateNotificationRoute(ctx context.Context, integrationID, destination string, targets TargetSelector, enabled bool) (*NotificationRoute, error) {
	return create[NotificationRoute](ctx, c, "/notification-routes", map[string]any{"integration_id": integrationID,
		"destination": destination, "targets": targets, "enabled": enabled})
}

// GetNotificationRoute finds a route (there is no single-route read).
func (c *Client) GetNotificationRoute(ctx context.Context, id string) (*NotificationRoute, error) {
	l, err := get[list[NotificationRoute]](ctx, c, "/notification-routes", nil)
	if err != nil {
		return nil, err
	}
	for _, r := range l.Items {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, notFound("/notification-routes/"+id, "notification route")
}

func (c *Client) DeleteNotificationRoute(ctx context.Context, id string) error {
	return c.del(ctx, "/notification-routes/"+esc(id))
}
