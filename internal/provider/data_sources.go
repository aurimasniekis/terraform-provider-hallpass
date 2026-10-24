package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---- hallpass_server

type serverDataSource struct{ baseDataSource }

// NewServerDataSource returns the hallpass_server data source.
func NewServerDataSource() datasource.DataSource { return &serverDataSource{} }

type serverDataModel struct {
	ID          types.String `tfsdk:"id"`
	Alias       types.String `tfsdk:"alias"`
	Kind        types.String `tfsdk:"kind"`
	DisplayName types.String `tfsdk:"display_name"`
	Address     types.String `tfsdk:"address"`
	Port        types.Int64  `tfsdk:"port"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (d *serverDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_server"
}

func (d *serverDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a server or git remote by alias.",
		Attributes: map[string]schema.Attribute{
			"alias":        schema.StringAttribute{MarkdownDescription: "Alias.", Required: true},
			"id":           schema.StringAttribute{MarkdownDescription: "Server ID.", Computed: true},
			"kind":         schema.StringAttribute{MarkdownDescription: "`ssh` or `git`.", Computed: true},
			"display_name": schema.StringAttribute{MarkdownDescription: "Display name.", Computed: true},
			"address":      schema.StringAttribute{MarkdownDescription: "Address.", Computed: true},
			"port":         schema.Int64Attribute{MarkdownDescription: "Port.", Computed: true},
			"enabled":      schema.BoolAttribute{MarkdownDescription: "Whether it is enabled.", Computed: true},
		},
	}
}

func (d *serverDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m serverDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := d.client.ListServers(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot list servers", err)
		return
	}
	for _, s := range items {
		if s.Alias == m.Alias.ValueString() {
			m.ID, m.Kind, m.DisplayName = types.StringValue(s.ID), types.StringValue(s.Kind), types.StringValue(s.DisplayName)
			m.Address, m.Port, m.Enabled = types.StringValue(s.Address), types.Int64Value(s.Port), types.BoolValue(s.Enabled)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.Diagnostics.AddError("Server not found", fmt.Sprintf("No server or git remote with alias %q.", m.Alias.ValueString()))
}

// ---- hallpass_agent

type agentDataSource struct{ baseDataSource }

// NewAgentDataSource returns the hallpass_agent data source.
func NewAgentDataSource() datasource.DataSource { return &agentDataSource{} }

type agentDataModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Groups  types.Set    `tfsdk:"groups"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func (d *agentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent"
}

func (d *agentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an agent by name.",
		Attributes: map[string]schema.Attribute{
			"name":    schema.StringAttribute{MarkdownDescription: "Name.", Required: true},
			"id":      schema.StringAttribute{MarkdownDescription: "Agent ID.", Computed: true},
			"groups":  schema.SetAttribute{MarkdownDescription: "Groups.", ElementType: types.StringType, Computed: true},
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether it is enabled.", Computed: true},
		},
	}
}

func (d *agentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m agentDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := d.client.ListAgents(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot list agents", err)
		return
	}
	for _, a := range items {
		if a.Name == m.Name.ValueString() {
			m.ID, m.Groups, m.Enabled = types.StringValue(a.ID), setOf(a.Groups), types.BoolValue(a.Enabled)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.Diagnostics.AddError("Agent not found", fmt.Sprintf("No agent named %q.", m.Name.ValueString()))
}

// ---- hallpass_role

type roleDataSource struct{ baseDataSource }

// NewRoleDataSource returns the hallpass_role data source.
func NewRoleDataSource() datasource.DataSource { return &roleDataSource{} }

type roleDataModel struct {
	ID         types.String `tfsdk:"id"`
	ServerID   types.String `tfsdk:"server_id"`
	Alias      types.String `tfsdk:"alias"`
	RemoteUser types.String `tfsdk:"remote_user"`
	Enabled    types.Bool   `tfsdk:"enabled"`
}

func (d *roleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (d *roleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a role or git access profile of a server by alias.",
		Attributes: map[string]schema.Attribute{
			"server_id":   schema.StringAttribute{MarkdownDescription: "Server or git remote ID.", Required: true},
			"alias":       schema.StringAttribute{MarkdownDescription: "Role alias.", Required: true},
			"id":          schema.StringAttribute{MarkdownDescription: "Role ID.", Computed: true},
			"remote_user": schema.StringAttribute{MarkdownDescription: "Remote account.", Computed: true},
			"enabled":     schema.BoolAttribute{MarkdownDescription: "Whether it is enabled.", Computed: true},
		},
	}
}

func (d *roleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m roleDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := d.client.ListRoles(ctx, m.ServerID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot list roles", err)
		return
	}
	for _, r := range items {
		if r.Alias == m.Alias.ValueString() {
			m.ID, m.RemoteUser, m.Enabled = types.StringValue(r.ID), types.StringValue(r.RemoteUser), types.BoolValue(r.Enabled)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.Diagnostics.AddError("Role not found", fmt.Sprintf("No role %q on server %s.", m.Alias.ValueString(), m.ServerID.ValueString()))
}

// ---- hallpass_operator

type operatorDataSource struct{ baseDataSource }

// NewOperatorDataSource returns the hallpass_operator data source.
func NewOperatorDataSource() datasource.DataSource { return &operatorDataSource{} }

type operatorDataModel struct {
	ID          types.String `tfsdk:"id"`
	Email       types.String `tfsdk:"email"`
	DisplayName types.String `tfsdk:"display_name"`
	Roles       types.Set    `tfsdk:"roles"`
	Groups      types.Set    `tfsdk:"groups"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (d *operatorDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_operator"
}

func (d *operatorDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an operator by email (for example for `hallpass_approver_rule`). Operators are invited and " +
			"managed in the console, not by Terraform.",
		Attributes: map[string]schema.Attribute{
			"email":        schema.StringAttribute{MarkdownDescription: "Email (case-insensitive).", Required: true},
			"id":           schema.StringAttribute{MarkdownDescription: "Operator ID.", Computed: true},
			"display_name": schema.StringAttribute{MarkdownDescription: "Display name.", Computed: true},
			"roles":        schema.SetAttribute{MarkdownDescription: "Operator roles.", ElementType: types.StringType, Computed: true},
			"groups":       schema.SetAttribute{MarkdownDescription: "Operator groups.", ElementType: types.StringType, Computed: true},
			"enabled":      schema.BoolAttribute{MarkdownDescription: "Whether the operator is enabled.", Computed: true},
		},
	}
}

func (d *operatorDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m operatorDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := d.client.ListOperators(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot list operators", err)
		return
	}
	for _, o := range items {
		if strings.EqualFold(o.Email, m.Email.ValueString()) {
			m.ID, m.DisplayName, m.Enabled = types.StringValue(o.ID), types.StringValue(o.DisplayName), types.BoolValue(o.Enabled)
			m.Roles, m.Groups = setOf(o.Roles), setOf(o.Groups)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.Diagnostics.AddError("Operator not found", fmt.Sprintf("No operator with email %q.", m.Email.ValueString()))
}

// ---- hallpass_gateway_host_keys

type gatewayKeysDataSource struct{ baseDataSource }

// NewGatewayHostKeysDataSource returns the hallpass_gateway_host_keys data source.
func NewGatewayHostKeysDataSource() datasource.DataSource { return &gatewayKeysDataSource{} }

type gatewayKeyModel struct {
	Algorithm   types.String `tfsdk:"algorithm"`
	PublicKey   types.String `tfsdk:"public_key"`
	Fingerprint types.String `tfsdk:"fingerprint"`
	State       types.String `tfsdk:"state"`
}

type gatewayKeysModel struct {
	Host       types.String      `tfsdk:"host"`
	Port       types.Int64       `tfsdk:"port"`
	Keys       []gatewayKeyModel `tfsdk:"keys"`
	KnownHosts types.String      `tfsdk:"known_hosts"`
}

func (d *gatewayKeysDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gateway_host_keys"
}

func (d *gatewayKeysDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The gateway's SSH host keys, for pinning in agents' `known_hosts` (agents must never trust the gateway on " +
			"first use). During a host-key rotation both keys are listed.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{MarkdownDescription: "Gateway host name agents connect to (for `known_hosts`).", Optional: true},
			"port": schema.Int64Attribute{MarkdownDescription: "Gateway SSH port (for `known_hosts`, default 22).", Optional: true},
			"keys": schema.ListNestedAttribute{MarkdownDescription: "Host keys.", Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"algorithm":   schema.StringAttribute{Computed: true, MarkdownDescription: "Algorithm."},
					"public_key":  schema.StringAttribute{Computed: true, MarkdownDescription: "Public key."},
					"fingerprint": schema.StringAttribute{Computed: true, MarkdownDescription: "SHA-256 fingerprint."},
					"state":       schema.StringAttribute{Computed: true, MarkdownDescription: "`active` or `staged` (during rotation)."},
				}}},
			"known_hosts": schema.StringAttribute{MarkdownDescription: "`known_hosts` lines for `host` and `port` (empty without `host`).",
				Computed: true},
		},
	}
}

func (d *gatewayKeysDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m gatewayKeysModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keys, err := d.client.ListGatewayHostKeys(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot list gateway host keys", err)
		return
	}
	host := m.Host.ValueString()
	if port := m.Port.ValueInt64(); host != "" && port != 0 && port != 22 {
		host = fmt.Sprintf("[%s]:%d", host, port)
	}
	var lines []string
	m.Keys = make([]gatewayKeyModel, 0, len(keys))
	for _, k := range keys {
		m.Keys = append(m.Keys, gatewayKeyModel{Algorithm: types.StringValue(k.Algorithm), PublicKey: types.StringValue(k.PublicKey),
			Fingerprint: types.StringValue(k.Fingerprint), State: types.StringValue(k.State)})
		if host != "" {
			lines = append(lines, host+" "+strings.TrimSpace(k.PublicKey))
		}
	}
	m.KnownHosts = types.StringValue(strings.Join(lines, "\n"))
	if len(lines) > 0 {
		m.KnownHosts = types.StringValue(strings.Join(lines, "\n") + "\n")
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
