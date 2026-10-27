package client

import (
	"context"
	"net/url"
)

// Agent is an AI agent identity.
type Agent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	SourceCIDRs []string          `json:"source_cidrs"`
	Groups      []string          `json:"groups"`
	Labels      map[string]string `json:"labels"`
	Version     int64             `json:"version"`
	DeletedAt   string            `json:"deleted_at,omitempty"`
	Keys        []AgentKey        `json:"keys,omitempty"`
}

// AgentKey is one public key of an agent.
type AgentKey struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Comment     string `json:"comment"`
	State       string `json:"state"`
}

// AgentInput creates or replaces an agent's attributes (enabled only applies on create).
type AgentInput struct {
	Version     int64             `json:"version,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     *bool             `json:"enabled,omitempty"`
	SourceCIDRs []string          `json:"source_cidrs"`
	Groups      []string          `json:"groups"`
	Labels      map[string]string `json:"labels"`
}

func (c *Client) CreateAgent(ctx context.Context, in AgentInput) (*Agent, error) {
	return create[Agent](ctx, c, "/agents", in)
}

func (c *Client) GetAgent(ctx context.Context, id string) (*Agent, error) {
	a, err := get[Agent](ctx, c, "/agents/"+esc(id), nil)
	if err == nil && a.DeletedAt != "" {
		return nil, notFound("/agents/"+id, "agent")
	}
	return a, err
}

func (c *Client) ListAgents(ctx context.Context) ([]Agent, error) {
	l, err := get[list[Agent]](ctx, c, "/agents", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (c *Client) UpdateAgent(ctx context.Context, id string, version int64, in AgentInput) (*Agent, error) {
	in.Enabled = nil
	in.Version = version
	return patch[Agent](ctx, c, "/agents/"+esc(id), version, in)
}

func (c *Client) SetAgentEnabled(ctx context.Context, id string, enabled bool) (*Agent, error) {
	if enabled {
		return post[Agent](ctx, c, "/agents/"+esc(id)+"/enable", nil)
	}
	return post[Agent](ctx, c, "/agents/"+esc(id)+"/disable", map[string]string{"reason": "Disabled by Terraform"})
}

func (c *Client) DeleteAgent(ctx context.Context, id string) error {
	return c.del(ctx, "/agents/"+esc(id))
}

func (c *Client) AddAgentKey(ctx context.Context, agentID, publicKey string) (*AgentKey, error) {
	return create[AgentKey](ctx, c, "/agents/"+esc(agentID)+"/keys", map[string]string{"public_key": publicKey})
}

// GetAgentKey finds a key in the agent's detail.
func (c *Client) GetAgentKey(ctx context.Context, agentID, keyID string) (*AgentKey, error) {
	a, err := c.GetAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	for _, k := range a.Keys {
		if k.ID == keyID {
			return &k, nil
		}
	}
	return nil, notFound("/agents/"+agentID+"/keys/"+keyID, "agent key")
}

func (c *Client) RevokeAgentKey(ctx context.Context, agentID, keyID string) error {
	_, err := post[AgentKey](ctx, c, "/agents/"+esc(agentID)+"/keys/"+esc(keyID)+"/revoke", map[string]string{"reason": "Removed by Terraform"})
	return err
}

// Server is a destination server or a git remote (Kind "git").
type Server struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Alias       string            `json:"alias"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Environment string            `json:"environment"`
	Address     string            `json:"address"`
	Port        int64             `json:"port"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata"`
	Groups      []string          `json:"groups"`
	Labels      map[string]string `json:"labels"`
	Version     int64             `json:"version"`
	DeletedAt   string            `json:"deleted_at,omitempty"`
	API         *APITarget        `json:"api,omitempty"`
}

// ServerInput creates or replaces a server's attributes (kind and enabled only apply on create).
type ServerInput struct {
	Version     int64             `json:"version,omitempty"`
	Kind        string            `json:"kind,omitempty"`
	Alias       string            `json:"alias"`
	DisplayName string            `json:"display_name,omitempty"`
	Description string            `json:"description"`
	Environment string            `json:"environment"`
	Address     string            `json:"address"`
	Port        int64             `json:"port"`
	Enabled     *bool             `json:"enabled,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	Groups      []string          `json:"groups"`
	Labels      map[string]string `json:"labels"`
	API         *APITarget        `json:"api,omitempty"`
}

func (c *Client) CreateServer(ctx context.Context, in ServerInput) (*Server, error) {
	return create[Server](ctx, c, "/servers", in)
}

func (c *Client) GetServer(ctx context.Context, id string) (*Server, error) {
	s, err := get[Server](ctx, c, "/servers/"+esc(id), nil)
	if err == nil && s.DeletedAt != "" {
		return nil, notFound("/servers/"+id, "server")
	}
	return s, err
}

func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	l, err := get[list[Server]](ctx, c, "/servers", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (c *Client) UpdateServer(ctx context.Context, id string, version int64, in ServerInput) (*Server, error) {
	in.Kind, in.Enabled, in.Version = "", nil, version
	return patch[Server](ctx, c, "/servers/"+esc(id), version, in)
}

func (c *Client) SetServerEnabled(ctx context.Context, id string, enabled bool) (*Server, error) {
	action := "/disable"
	if enabled {
		action = "/enable"
	}
	return post[Server](ctx, c, "/servers/"+esc(id)+action, nil)
}

func (c *Client) DeleteServer(ctx context.Context, id string) error {
	return c.del(ctx, "/servers/"+esc(id))
}

// HostIdentity is a pinned destination host key.
type HostIdentity struct {
	ID          string `json:"id"`
	ServerID    string `json:"server_id"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
	EnrolledVia string `json:"enrolled_via"`
}

// AddHostIdentity pins a host key (it is trusted immediately).
func (c *Client) AddHostIdentity(ctx context.Context, serverID, publicKey string) (*HostIdentity, error) {
	return create[HostIdentity](ctx, c, "/servers/"+esc(serverID)+"/host-identities", map[string]string{"public_key": publicKey})
}

func (c *Client) ListHostIdentities(ctx context.Context, serverID string) ([]HostIdentity, error) {
	l, err := get[list[HostIdentity]](ctx, c, "/servers/"+esc(serverID)+"/host-identities", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

// GetHostIdentity finds a host identity of a server; retired identities read as not found.
func (c *Client) GetHostIdentity(ctx context.Context, serverID, id string) (*HostIdentity, error) {
	items, err := c.ListHostIdentities(ctx, serverID)
	if err != nil {
		return nil, err
	}
	for _, h := range items {
		if h.ID == id && h.State != "retired" {
			return &h, nil
		}
	}
	return nil, notFound("/servers/"+serverID+"/host-identities/"+id, "host identity")
}

func (c *Client) RetireHostIdentity(ctx context.Context, id string) error {
	_, err := post[HostIdentity](ctx, c, "/host-identities/"+esc(id)+"/retire", nil)
	return err
}

// GitRules are the repository and push rules of a git access profile.
type GitRules struct {
	Repos []string  `json:"repos"`
	Push  *PushRule `json:"push,omitempty"`
}

// PushRule limits what a push may change.
type PushRule struct {
	Branches          []string `json:"branches"`
	ProtectedBranches []string `json:"protected_branches"`
	Tags              []string `json:"tags"`
	AllowDelete       bool     `json:"allow_delete"`
	AllowForcePush    bool     `json:"allow_force_push"`
}

// Role is a server role or a git access profile.
type Role struct {
	ID                    string            `json:"id"`
	ServerID              string            `json:"server_id"`
	Alias                 string            `json:"alias"`
	DisplayName           string            `json:"display_name"`
	Description           string            `json:"description"`
	RemoteUser            string            `json:"remote_user"`
	Capabilities          []string          `json:"capabilities"`
	DefaultDuration       int64             `json:"default_duration"`
	MaxDuration           int64             `json:"max_duration"`
	MaxConcurrent         int64             `json:"max_concurrent"`
	MaxConcurrentPerAgent int64             `json:"max_concurrent_per_agent"`
	RecordInput           bool              `json:"record_input"`
	RecordingMode         string            `json:"recording_mode"`
	EnvAllow              []string          `json:"env_allow"`
	ApprovalChannels      []string          `json:"approval_channels"`
	RestrictionNotes      string            `json:"restriction_notes"`
	RetentionClass        string            `json:"retention_class"`
	Labels                map[string]string `json:"labels"`
	Enabled               bool              `json:"enabled"`
	Version               int64             `json:"version"`
	Git                   *GitRules         `json:"git,omitempty"`
	API                   *APIRules         `json:"api,omitempty"`
	ApprovalsRequired     int64             `json:"approvals_required"`
	DeletedAt             string            `json:"deleted_at,omitempty"`
}

// RoleInput creates or replaces a role (enabled only applies on create; use SetRoleEnabled afterwards).
type RoleInput struct {
	Version               int64             `json:"version,omitempty"`
	Alias                 string            `json:"alias"`
	DisplayName           string            `json:"display_name,omitempty"`
	Description           string            `json:"description"`
	RemoteUser            string            `json:"remote_user,omitempty"`
	Capabilities          []string          `json:"capabilities"`
	DefaultDuration       int64             `json:"default_duration"`
	MaxDuration           int64             `json:"max_duration"`
	MaxConcurrent         int64             `json:"max_concurrent,omitempty"`
	MaxConcurrentPerAgent int64             `json:"max_concurrent_per_agent,omitempty"`
	RecordInput           *bool             `json:"record_input,omitempty"`
	RecordingMode         string            `json:"recording_mode,omitempty"`
	EnvAllow              []string          `json:"env_allow,omitempty"`
	ApprovalChannels      []string          `json:"approval_channels,omitempty"`
	RestrictionNotes      *string           `json:"restriction_notes,omitempty"`
	RetentionClass        string            `json:"retention_class,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Enabled               *bool             `json:"enabled,omitempty"`
	Git                   *GitRules         `json:"git,omitempty"`
	API                   *APIRules         `json:"api,omitempty"`
	ApprovalsRequired     int64             `json:"approvals_required,omitempty"`
}

func (c *Client) CreateRole(ctx context.Context, serverID string, in RoleInput) (*Role, error) {
	return create[Role](ctx, c, "/servers/"+esc(serverID)+"/roles", in)
}

func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	r, err := get[Role](ctx, c, "/roles/"+esc(id), nil)
	if err == nil && r.DeletedAt != "" {
		return nil, notFound("/roles/"+id, "role")
	}
	return r, err
}

func (c *Client) ListRoles(ctx context.Context, serverID string) ([]Role, error) {
	l, err := get[list[Role]](ctx, c, "/servers/"+esc(serverID)+"/roles", nil)
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (c *Client) UpdateRole(ctx context.Context, id string, version int64, in RoleInput) (*Role, error) {
	in.Enabled, in.Version = nil, version
	return patch[Role](ctx, c, "/roles/"+esc(id), version, in)
}

func (c *Client) SetRoleEnabled(ctx context.Context, id string, enabled bool) (*Role, error) {
	action := "/disable"
	if enabled {
		action = "/enable"
	}
	return post[Role](ctx, c, "/roles/"+esc(id)+action, nil)
}

func (c *Client) DeleteRole(ctx context.Context, id string) error {
	return c.del(ctx, "/roles/"+esc(id))
}

// LoginCredential is a login key of a role.
type LoginCredential struct {
	ID                 string `json:"id"`
	RoleID             string `json:"role_id"`
	Kind               string `json:"kind"`
	Algorithm          string `json:"algorithm"`
	PublicKey          string `json:"public_key"`
	Fingerprint        string `json:"fingerprint"`
	State              string `json:"state"`
	ProbeOKAt          string `json:"probe_ok_at,omitempty"`
	ProbeError         string `json:"probe_error,omitempty"`
	ActivatedAt        string `json:"activated_at,omitempty"`
	AuthorizedKeysLine string `json:"authorized_keys_line"`
}

func (c *Client) GenerateCredential(ctx context.Context, roleID string) (*LoginCredential, error) {
	return create[LoginCredential](ctx, c, "/roles/"+esc(roleID)+"/credentials:generate", nil)
}

// GetCredential finds a credential of a role.
func (c *Client) GetCredential(ctx context.Context, roleID, id string) (*LoginCredential, error) {
	l, err := get[list[LoginCredential]](ctx, c, "/roles/"+esc(roleID)+"/credentials", nil)
	if err != nil {
		return nil, err
	}
	for _, cr := range l.Items {
		if cr.ID == id {
			return &cr, nil
		}
	}
	return nil, notFound("/roles/"+roleID+"/credentials/"+id, "login key")
}

// ProbeCredential tests the login on the destination; a failed probe is an error with the reason.
func (c *Client) ProbeCredential(ctx context.Context, id string) (*LoginCredential, error) {
	return post[LoginCredential](ctx, c, "/credentials/"+esc(id)+"/probe", nil)
}

func (c *Client) ActivateCredential(ctx context.Context, id string, force bool) (*LoginCredential, error) {
	q := url.Values{}
	if force {
		q.Set("force", "true")
	}
	return call[LoginCredential](ctx, c, &request{method: "POST", path: "/credentials/" + esc(id) + "/activate", query: q})
}

func (c *Client) RevokeCredential(ctx context.Context, id string) error {
	_, err := post[LoginCredential](ctx, c, "/credentials/"+esc(id)+"/revoke", map[string]string{"reason": "Removed by Terraform"})
	return err
}
