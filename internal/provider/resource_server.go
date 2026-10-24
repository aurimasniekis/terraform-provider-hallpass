package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// serverResource implements hallpass_server (kind "ssh") and hallpass_git_remote (kind "git"): both are servers in
// HallPass, with a kind fixed at creation.
type serverResource struct {
	baseResource
	kind string
}

var (
	_ resource.ResourceWithImportState = (*serverResource)(nil)
)

// NewServerResource returns the hallpass_server resource.
func NewServerResource() resource.Resource { return &serverResource{kind: "ssh"} }

// NewGitRemoteResource returns the hallpass_git_remote resource.
func NewGitRemoteResource() resource.Resource { return &serverResource{kind: "git"} }

type serverModel struct {
	ID          types.String `tfsdk:"id"`
	Alias       types.String `tfsdk:"alias"`
	DisplayName types.String `tfsdk:"display_name"`
	Description types.String `tfsdk:"description"`
	Environment types.String `tfsdk:"environment"`
	Address     types.String `tfsdk:"address"`
	Port        types.Int64  `tfsdk:"port"`
	Metadata    types.Map    `tfsdk:"metadata"`
	Groups      types.Set    `tfsdk:"groups"`
	Labels      types.Map    `tfsdk:"labels"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (r *serverResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	if r.kind == "git" {
		resp.TypeName = req.ProviderTypeName + "_git_remote"
		return
	}
	resp.TypeName = req.ProviderTypeName + "_server"
}

func (r *serverResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	what, desc := "server", "A destination server agents reach through the gateway. Pin its host key with `hallpass_host_key` and add "+
		"roles with `hallpass_role`. Destroying it deletes the server and all of its roles: access ends, login keys are revoked, and "+
		"the record stays only so history can name it. Import with the server ID."
	addressDesc := "Host name or IP address the gateway connects to. It must be inside the gateway's `egress.allow_cidrs`."
	if r.kind == "git" {
		what, desc = "git remote", "A git host (GitHub, GitLab, your own server) agents clone from and push to with plain git through the "+
			"gateway. Pin its host keys with `hallpass_host_key` and add `hallpass_git_access_profile`s. The alias is the first part "+
			"of every repository path agents use (`git clone center:<alias>/<owner>/<repo>.git`). Destroying it deletes the remote "+
			"and its profiles. Import with the server ID."
		addressDesc = "Host name of the git host, e.g. `github.com`. Its SSH address ranges must be inside the gateway's " +
			"`egress.allow_cidrs`."
	}
	attrs := map[string]schema.Attribute{
		"id":    idAttribute("Server ID (`srv_…`)."),
		"alias": schema.StringAttribute{MarkdownDescription: "Unique name agents use. Gateway command words are reserved.", Required: true, Validators: aliasValidators()},
		"display_name": schema.StringAttribute{MarkdownDescription: "Display name (defaults to the alias).", Optional: true, Computed: true,
			Validators:    []validator.String{stringvalidator.LengthBetween(1, 200)},
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"description": descriptionAttribute(2000),
		"address":     schema.StringAttribute{MarkdownDescription: addressDesc, Required: true},
		"port": schema.Int64Attribute{MarkdownDescription: "SSH port.", Optional: true, Computed: true, Default: int64default.StaticInt64(22),
			Validators: []validator.Int64{int64validator.Between(1, 65535)}},
		"groups":  groupsAttribute(what),
		"labels":  labelsAttribute(what),
		"enabled": enabledAttribute(what),
	}
	if r.kind == "ssh" {
		attrs["environment"] = schema.StringAttribute{MarkdownDescription: "Environment, e.g. `production` (informational).",
			Optional: true, Computed: true, Default: stringdefault.StaticString("")}
		attrs["metadata"] = schema.MapAttribute{MarkdownDescription: "Free-form metadata (informational).", ElementType: types.StringType,
			Optional: true, Computed: true, Default: mapdefault.StaticValue(mapOf(nil))}
	} else {
		attrs["environment"] = computedString("Always empty for git remotes.")
		attrs["metadata"] = schema.MapAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Always empty for git remotes.",
			PlanModifiers: []planmodifier.Map{mapplanmodifier.UseStateForUnknown()}}
	}
	resp.Schema = schema.Schema{MarkdownDescription: desc, Attributes: attrs}
}

func (m *serverModel) fill(s *client.Server) {
	m.ID = types.StringValue(s.ID)
	m.Alias = types.StringValue(s.Alias)
	m.DisplayName = types.StringValue(s.DisplayName)
	m.Description = types.StringValue(s.Description)
	m.Environment = types.StringValue(s.Environment)
	m.Address = types.StringValue(s.Address)
	m.Port = types.Int64Value(s.Port)
	m.Metadata = mapOf(s.Metadata)
	m.Groups = setOf(s.Groups)
	m.Labels = mapOf(s.Labels)
	m.Enabled = types.BoolValue(s.Enabled)
}

func (r *serverResource) toInput(ctx context.Context, m serverModel, d *diag.Diagnostics) client.ServerInput {
	in := client.ServerInput{Alias: m.Alias.ValueString(), Description: m.Description.ValueString(), Address: m.Address.ValueString(),
		Port: m.Port.ValueInt64(), Groups: stringsOf(ctx, m.Groups, d), Labels: stringMapOf(ctx, m.Labels, d), Metadata: map[string]string{}}
	if !m.DisplayName.IsUnknown() && !m.DisplayName.IsNull() {
		in.DisplayName = m.DisplayName.ValueString()
	}
	if r.kind == "ssh" {
		in.Environment = m.Environment.ValueString()
		in.Metadata = stringMapOf(ctx, m.Metadata, d)
	}
	return in
}

func (r *serverResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serverModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := r.toInput(ctx, plan, &resp.Diagnostics)
	in.Kind, in.Enabled = r.kind, ptr(plan.Enabled.ValueBool())
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.CreateServer(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create "+r.noun(), err)
		return
	}
	plan.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, s.Version)...)
}

func (r *serverResource) noun() string {
	if r.kind == "git" {
		return "git remote"
	}
	return "server"
}

func (r *serverResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serverModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.GetServer(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read "+r.noun(), err)
		return
	}
	if s.Kind != r.kind {
		resp.Diagnostics.AddError("Wrong resource type", "HallPass server "+s.ID+" is of kind "+s.Kind+
			"; manage git remotes with hallpass_git_remote and other servers with hallpass_server.")
		return
	}
	state.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, s.Version)...)
}

func (r *serverResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state serverModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := r.toInput(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	s, err := r.client.UpdateServer(ctx, id, loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update "+r.noun(), err)
		return
	}
	if s.Enabled != plan.Enabled.ValueBool() {
		if s, err = r.client.SetServerEnabled(ctx, id, plan.Enabled.ValueBool()); err != nil {
			apiError(&resp.Diagnostics, "Cannot change whether the "+r.noun()+" is enabled", err)
			return
		}
	}
	plan.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, s.Version)...)
}

func (r *serverResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serverModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteServer(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete "+r.noun(), err)
	}
}

func (r *serverResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
