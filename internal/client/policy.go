package client

import "context"

// LabelRequirement is one label expression (operator In, NotIn, Exists or DoesNotExist).
type LabelRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// LabelSelector matches labels; an empty selector matches nothing.
type LabelSelector struct {
	MatchLabels      map[string]string  `json:"matchLabels,omitempty"`
	MatchExpressions []LabelRequirement `json:"matchExpressions,omitempty"`
}

// SubjectSelector selects agents.
type SubjectSelector struct {
	All         bool           `json:"all,omitempty"`
	Agents      []string       `json:"agents,omitempty"`
	AgentGroups []string       `json:"agent_groups,omitempty"`
	AgentLabels *LabelSelector `json:"agent_labels,omitempty"`
}

// TargetSelector selects servers and git remotes.
type TargetSelector struct {
	All          bool           `json:"all,omitempty"`
	Servers      []string       `json:"servers,omitempty"`
	ServerGroups []string       `json:"server_groups,omitempty"`
	ServerLabels *LabelSelector `json:"server_labels,omitempty"`
}

// RoleSelector selects roles and access profiles.
type RoleSelector struct {
	All        bool           `json:"all,omitempty"`
	Names      []string       `json:"names,omitempty"`
	IDs        []string       `json:"ids,omitempty"`
	RoleLabels *LabelSelector `json:"role_labels,omitempty"`
}

// OperatorSelector selects operators for approver rules.
type OperatorSelector struct {
	All            bool     `json:"all,omitempty"`
	Operators      []string `json:"operators,omitempty"`
	OperatorGroups []string `json:"operator_groups,omitempty"`
}

// PolicyRule is an access rule. Durations are seconds.
type PolicyRule struct {
	ID              string          `json:"id,omitempty"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Effect          string          `json:"effect"`
	Level           string          `json:"level,omitempty"`
	Subjects        SubjectSelector `json:"subjects"`
	Targets         TargetSelector  `json:"targets"`
	Roles           RoleSelector    `json:"roles"`
	MaxDuration     int64           `json:"max_duration,omitempty"`
	AutoMaxDuration int64           `json:"auto_max_duration,omitempty"`
	RequireReason   *bool           `json:"require_reason,omitempty"`
	Enabled         bool            `json:"enabled"`
	Version         int64           `json:"version,omitempty"`
}

func (c *Client) CreatePolicyRule(ctx context.Context, in PolicyRule) (*PolicyRule, error) {
	in.ID, in.Version = "", 0
	return create[PolicyRule](ctx, c, "/policy/rules", in)
}

func (c *Client) GetPolicyRule(ctx context.Context, id string) (*PolicyRule, error) {
	return get[PolicyRule](ctx, c, "/policy/rules/"+esc(id), nil)
}

// UpdatePolicyRule replaces the rule.
func (c *Client) UpdatePolicyRule(ctx context.Context, id string, version int64, in PolicyRule) (*PolicyRule, error) {
	in.ID, in.Version = "", version
	return patch[PolicyRule](ctx, c, "/policy/rules/"+esc(id), version, in)
}

func (c *Client) DeletePolicyRule(ctx context.Context, id string) error {
	return c.del(ctx, "/policy/rules/"+esc(id))
}

// ApproverRule says which operators may decide which requests. Durations are seconds.
type ApproverRule struct {
	ID          string           `json:"id,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Operators   OperatorSelector `json:"operators"`
	Targets     TargetSelector   `json:"targets"`
	Roles       RoleSelector     `json:"roles"`
	MaxDuration int64            `json:"max_duration,omitempty"`
	Enabled     bool             `json:"enabled"`
	Version     int64            `json:"version,omitempty"`
}

func (c *Client) CreateApproverRule(ctx context.Context, in ApproverRule) (*ApproverRule, error) {
	in.ID, in.Version = "", 0
	return create[ApproverRule](ctx, c, "/policy/approver-rules", in)
}

// GetApproverRule finds an approver rule (there is no single-rule read).
func (c *Client) GetApproverRule(ctx context.Context, id string) (*ApproverRule, error) {
	l, err := get[list[ApproverRule]](ctx, c, "/policy/approver-rules", nil)
	if err != nil {
		return nil, err
	}
	for _, r := range l.Items {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, notFound("/policy/approver-rules/"+id, "approver rule")
}

func (c *Client) UpdateApproverRule(ctx context.Context, id string, version int64, in ApproverRule) (*ApproverRule, error) {
	in.ID, in.Version = "", version
	return patch[ApproverRule](ctx, c, "/policy/approver-rules/"+esc(id), version, in)
}

func (c *Client) DeleteApproverRule(ctx context.Context, id string) error {
	return c.del(ctx, "/policy/approver-rules/"+esc(id))
}

// SelfApproval is the installation-wide self-approval setting.
type SelfApproval struct {
	ProhibitSelfApproval bool `json:"prohibit_self_approval"`
}

func (c *Client) GetSelfApproval(ctx context.Context) (*SelfApproval, error) {
	return get[SelfApproval](ctx, c, "/policy/self-approval", nil)
}

func (c *Client) SetSelfApproval(ctx context.Context, in SelfApproval) (*SelfApproval, error) {
	return put[SelfApproval](ctx, c, "/policy/self-approval", in)
}
