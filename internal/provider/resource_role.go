package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var _ resource.ResourceWithImportState = (*roleResource)(nil)

type roleResource struct{ baseResource }

// NewRoleResource returns the hallpass_role resource.
func NewRoleResource() resource.Resource { return &roleResource{} }

type roleModel struct {
	ID                    types.String `tfsdk:"id"`
	ServerID              types.String `tfsdk:"server_id"`
	Alias                 types.String `tfsdk:"alias"`
	DisplayName           types.String `tfsdk:"display_name"`
	Description           types.String `tfsdk:"description"`
	RemoteUser            types.String `tfsdk:"remote_user"`
	Capabilities          types.Set    `tfsdk:"capabilities"`
	DefaultDuration       types.String `tfsdk:"default_duration"`
	MaxDuration           types.String `tfsdk:"max_duration"`
	MaxConcurrent         types.Int64  `tfsdk:"max_concurrent"`
	MaxConcurrentPerAgent types.Int64  `tfsdk:"max_concurrent_per_agent"`
	RecordInput           types.Bool   `tfsdk:"record_input"`
	RecordingMode         types.String `tfsdk:"recording_mode"`
	EnvAllow              types.Set    `tfsdk:"env_allow"`
	ApprovalChannels      types.Set    `tfsdk:"approval_channels"`
	RestrictionNotes      types.String `tfsdk:"restriction_notes"`
	ApprovalsRequired     types.Int64  `tfsdk:"approvals_required"`
	Labels                types.Map    `tfsdk:"labels"`
	Enabled               types.Bool   `tfsdk:"enabled"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func durationAttribute(desc, def string) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: desc + " A duration such as `30m` or `4h`.", Optional: true, Computed: true,
		Default: stringdefault.StaticString(def), Validators: []validator.String{durationValidator()}}
}

func approvalsRequiredAttribute() schema.Int64Attribute {
	return schema.Int64Attribute{
		MarkdownDescription: "Distinct approvers each request needs (1-5). Above 1, policy never approves automatically and any one " +
			"denial ends the request.",
		Optional: true, Computed: true, Default: int64default.StaticInt64(1), Validators: []validator.Int64{int64validator.Between(1, 5)},
	}
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A role on a server: the account the gateway logs in as and the limits of the access agents request. " +
			"Give it a login key with `hallpass_login_key`, and decide who may use it with `hallpass_policy_rule`. Destroying it deletes " +
			"the role: access ends and its login keys are revoked. For git remotes use `hallpass_git_access_profile`. Import with the " +
			"role ID.",
		Attributes: map[string]schema.Attribute{
			"id":        idAttribute("Role ID (`rol_…`)."),
			"server_id": parentAttribute("Server ID (`srv_…`).", "srv"),
			"alias":     schema.StringAttribute{MarkdownDescription: "Name agents request (`--role`), unique on the server.", Required: true, Validators: aliasValidators()},
			"display_name": schema.StringAttribute{MarkdownDescription: "Display name (defaults to the alias).", Optional: true, Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"description": descriptionAttribute(2000),
			"remote_user": schema.StringAttribute{MarkdownDescription: "Account on the server the gateway logs in as.", Required: true,
				Validators: []validator.String{stringvalidator.LengthBetween(1, 64)}},
			"capabilities": schema.SetAttribute{
				MarkdownDescription: "What agents may do: `shell` (interactive), `exec` (commands), `pty` (terminal) and `file-transfer` " +
					"(scp and sftp).",
				ElementType: types.StringType, Optional: true, Computed: true,
				Default: setdefault.StaticValue(setOf([]string{"exec", "pty", "shell"})),
				Validators: []validator.Set{setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(stringvalidator.OneOf("shell", "exec", "pty", "file-transfer"))},
			},
			"default_duration": durationAttribute("Access duration when the agent does not ask for one.", "30m"),
			"max_duration":     durationAttribute("Longest access an agent may request (policy may lower it).", "6h"),
			"max_concurrent": schema.Int64Attribute{MarkdownDescription: "Concurrent connections across all agents.", Optional: true, Computed: true,
				Default: int64default.StaticInt64(10), Validators: []validator.Int64{int64validator.AtLeast(1)}},
			"max_concurrent_per_agent": schema.Int64Attribute{MarkdownDescription: "Concurrent connections per agent.", Optional: true,
				Computed: true, Default: int64default.StaticInt64(2), Validators: []validator.Int64{int64validator.AtLeast(1)}},
			"record_input": schema.BoolAttribute{MarkdownDescription: "Also record what the agent types (may capture secrets).", Optional: true,
				Computed: true, Default: booldefault.StaticBool(false)},
			"recording_mode": schema.StringAttribute{
				MarkdownDescription: "`mandatory` (no access without a working recording) or `best_effort`.", Optional: true, Computed: true,
				Default: stringdefault.StaticString("mandatory"), Validators: []validator.String{stringvalidator.OneOf("mandatory", "best_effort")}},
			"env_allow": schema.SetAttribute{MarkdownDescription: "Environment variables agents may pass (`LANG`, `LC_*`).",
				ElementType: types.StringType, Optional: true, Computed: true, Default: setdefault.StaticValue(setOf(nil))},
			"approval_channels": schema.SetAttribute{
				MarkdownDescription: "Where requests may be approved: `web`, `slack`, `telegram`.",
				ElementType:         types.StringType, Optional: true, Computed: true,
				Default: setdefault.StaticValue(setOf([]string{"slack", "telegram", "web"})),
				Validators: []validator.Set{setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(stringvalidator.OneOf("web", "slack", "telegram"))},
			},
			"restriction_notes": schema.StringAttribute{MarkdownDescription: "Notes on what the account may do (shown to approvers).",
				Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"approvals_required": approvalsRequiredAttribute(),
			"labels":             labelsAttribute("role"),
			"enabled":            enabledAttribute("role"),
		},
	}
}

func (m *roleModel) fill(ro *client.Role) {
	m.ID = types.StringValue(ro.ID)
	m.ServerID = types.StringValue(ro.ServerID)
	m.Alias = types.StringValue(ro.Alias)
	m.DisplayName = types.StringValue(ro.DisplayName)
	m.Description = types.StringValue(ro.Description)
	m.RemoteUser = types.StringValue(ro.RemoteUser)
	m.Capabilities = setOf(ro.Capabilities)
	m.DefaultDuration = durationOf(m.DefaultDuration, ro.DefaultDuration)
	m.MaxDuration = durationOf(m.MaxDuration, ro.MaxDuration)
	m.MaxConcurrent = types.Int64Value(ro.MaxConcurrent)
	m.MaxConcurrentPerAgent = types.Int64Value(ro.MaxConcurrentPerAgent)
	m.RecordInput = types.BoolValue(ro.RecordInput)
	m.RecordingMode = types.StringValue(ro.RecordingMode)
	m.EnvAllow = setOf(ro.EnvAllow)
	m.ApprovalChannels = setOf(ro.ApprovalChannels)
	m.RestrictionNotes = types.StringValue(ro.RestrictionNotes)
	m.ApprovalsRequired = types.Int64Value(ro.ApprovalsRequired)
	m.Labels = mapOf(ro.Labels)
	m.Enabled = types.BoolValue(ro.Enabled)
}

func (m roleModel) input(ctx context.Context, d *diag.Diagnostics) client.RoleInput {
	in := client.RoleInput{Alias: m.Alias.ValueString(), Description: m.Description.ValueString(), RemoteUser: m.RemoteUser.ValueString(),
		Capabilities: stringsOf(ctx, m.Capabilities, d), DefaultDuration: seconds(m.DefaultDuration), MaxDuration: seconds(m.MaxDuration),
		MaxConcurrent: m.MaxConcurrent.ValueInt64(), MaxConcurrentPerAgent: m.MaxConcurrentPerAgent.ValueInt64(),
		RecordInput: ptr(m.RecordInput.ValueBool()), RecordingMode: m.RecordingMode.ValueString(), EnvAllow: stringsOf(ctx, m.EnvAllow, d),
		ApprovalChannels: stringsOf(ctx, m.ApprovalChannels, d), RestrictionNotes: ptr(m.RestrictionNotes.ValueString()),
		ApprovalsRequired: m.ApprovalsRequired.ValueInt64(), Labels: stringMapOf(ctx, m.Labels, d)}
	if !m.DisplayName.IsUnknown() && !m.DisplayName.IsNull() {
		in.DisplayName = m.DisplayName.ValueString()
	}
	return in
}

// roleCRUD is shared by hallpass_role, hallpass_git_access_profile and hallpass_api_access_profile: all are roles
// in HallPass.
type roleCRUD[M any] struct {
	client *client.Client
	noun   string
	input  func(ctx context.Context, m M, d *diag.Diagnostics) client.RoleInput
	fill   func(m *M, ro *client.Role)
	ids    func(m *M) (id, serverID types.String)
	on     func(m *M) bool
	// kind is the server kind the role must belong to: "ssh", "git" or "api".
	kind string
}

// resourceForKind names the resource that manages roles of a server kind.
var resourceForKind = map[string]string{"ssh": "hallpass_role", "git": "hallpass_git_access_profile", "api": "hallpass_api_access_profile"}

// roleKind infers a role's server kind from its rules.
func roleKind(ro *client.Role) string {
	switch {
	case ro.Git != nil:
		return "git"
	case ro.API != nil:
		return "api"
	}
	return "ssh"
}

func (c roleCRUD[M]) create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := c.input(ctx, plan, &resp.Diagnostics)
	in.Enabled = ptr(c.on(&plan))
	if resp.Diagnostics.HasError() {
		return
	}
	_, serverID := c.ids(&plan)
	ro, err := c.client.CreateRole(ctx, serverID.ValueString(), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create "+c.noun, err)
		return
	}
	c.fill(&plan, ro)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, ro.Version)...)
}

func (c roleCRUD[M]) read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, _ := c.ids(&state)
	ro, err := c.client.GetRole(ctx, id.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read "+c.noun, err)
		return
	}
	if k := roleKind(ro); k != c.kind {
		resp.Diagnostics.AddError("Wrong resource type", "HallPass role "+ro.ID+" belongs to a server of kind "+k+"; manage it with "+
			resourceForKind[k]+".")
		return
	}
	c.fill(&state, ro)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, ro.Version)...)
}

func (c roleCRUD[M]) update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := c.input(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	idV, _ := c.ids(&state)
	id := idV.ValueString()
	ro, err := c.client.UpdateRole(ctx, id, loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update "+c.noun, err)
		return
	}
	if want := c.on(&plan); ro.Enabled != want {
		if ro, err = c.client.SetRoleEnabled(ctx, id, want); err != nil {
			apiError(&resp.Diagnostics, "Cannot change whether the "+c.noun+" is enabled", err)
			return
		}
	}
	c.fill(&plan, ro)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, ro.Version)...)
}

func (c roleCRUD[M]) delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, _ := c.ids(&state)
	if err := c.client.DeleteRole(ctx, id.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete "+c.noun, err)
	}
}

func (r *roleResource) crud() roleCRUD[roleModel] {
	return roleCRUD[roleModel]{client: r.client, noun: "role", kind: "ssh",
		input: func(ctx context.Context, m roleModel, d *diag.Diagnostics) client.RoleInput { return m.input(ctx, d) },
		fill:  func(m *roleModel, ro *client.Role) { m.fill(ro) },
		ids:   func(m *roleModel) (types.String, types.String) { return m.ID, m.ServerID },
		on:    func(m *roleModel) bool { return m.Enabled.ValueBool() }}
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.crud().create(ctx, req, resp)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.crud().read(ctx, req, resp)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.crud().update(ctx, req, resp)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.crud().delete(ctx, req, resp)
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
