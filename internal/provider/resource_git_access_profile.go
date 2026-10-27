package provider

import (
	"context"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var (
	_ resource.ResourceWithImportState    = (*gitProfileResource)(nil)
	_ resource.ResourceWithValidateConfig = (*gitProfileResource)(nil)
)

type gitProfileResource struct{ baseResource }

// NewGitAccessProfileResource returns the hallpass_git_access_profile resource.
func NewGitAccessProfileResource() resource.Resource { return &gitProfileResource{} }

type gitProfileModel struct {
	ID                types.String `tfsdk:"id"`
	ServerID          types.String `tfsdk:"server_id"`
	Alias             types.String `tfsdk:"alias"`
	Description       types.String `tfsdk:"description"`
	RemoteUser        types.String `tfsdk:"remote_user"`
	Repositories      types.Set    `tfsdk:"repositories"`
	AllowPush         types.Bool   `tfsdk:"allow_push"`
	Branches          types.Set    `tfsdk:"branches"`
	ProtectedBranches types.Set    `tfsdk:"protected_branches"`
	Tags              types.Set    `tfsdk:"tags"`
	AllowBranchDelete types.Bool   `tfsdk:"allow_branch_delete"`
	AllowForcePush    types.Bool   `tfsdk:"allow_force_push"`
	ApprovalsRequired types.Int64  `tfsdk:"approvals_required"`
	DefaultDuration   types.String `tfsdk:"default_duration"`
	MaxDuration       types.String `tfsdk:"max_duration"`
	Labels            types.Map    `tfsdk:"labels"`
	Enabled           types.Bool   `tfsdk:"enabled"`
}

func (r *gitProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_git_access_profile"
}

func patternSet(desc string) schema.SetAttribute {
	return schema.SetAttribute{MarkdownDescription: desc, ElementType: types.StringType, Optional: true,
		Validators: []validator.Set{setvalidator.SizeAtLeast(1)}}
}

func (r *gitProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An access profile of a git remote: which repositories agents may clone, fetch and push, with which " +
			"push rules, and the login key the gateway uses (`hallpass_login_key`; on GitHub add its `public_key` as a deploy key). " +
			"Patterns match repository paths without `.git`, case-insensitively: `*` within one segment, `**` across segments, `?` " +
			"one character, `{a,b}` alternatives. Destroying it deletes the profile and revokes its login keys. Import with the role ID.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("Profile ID (`rol_…`)."),
			"server_id":   parentAttribute("Git remote ID (`srv_…`).", "srv"),
			"alias":       schema.StringAttribute{MarkdownDescription: "Profile name, unique on the remote.", Required: true, Validators: aliasValidators()},
			"description": descriptionAttribute(2000),
			"remote_user": schema.StringAttribute{MarkdownDescription: "Account on the git host (`git` for GitHub, GitLab and Bitbucket).",
				Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"repositories": schema.SetAttribute{MarkdownDescription: "Repository patterns, e.g. `acme/{api,web}` or `acme/**`.",
				ElementType: types.StringType, Required: true, Validators: []validator.Set{setvalidator.SizeAtLeast(1)}},
			"allow_push": schema.BoolAttribute{MarkdownDescription: "Allow pushing (limited by the branch and tag rules); otherwise clone and fetch only.",
				Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"branches":           patternSet("Branches agents may create and update, relative to `refs/heads/` (e.g. `agent/**`). Needs `allow_push`."),
			"protected_branches": patternSet("Branches never changed, even when `branches` matches (e.g. `main`)."),
			"tags":               patternSet("Tags agents may create (existing tags are never moved or deleted). Empty: no tags."),
			"allow_branch_delete": schema.BoolAttribute{MarkdownDescription: "Allow deleting branches that `branches` matches.",
				Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"allow_force_push": schema.BoolAttribute{MarkdownDescription: "Allow rewriting branch history. Off: every branch update must be a " +
				"fast-forward HallPass can prove from the pushed commits.", Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"approvals_required": approvalsRequiredAttribute(),
			"default_duration":   durationAttribute("Access duration when the agent does not ask for one.", "30m"),
			"max_duration":       durationAttribute("Longest access an agent may request (policy may lower it).", "6h"),
			"labels":             labelsAttribute("profile"),
			"enabled":            enabledAttribute("profile"),
		},
	}
}

func (r *gitProfileResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m gitProfileModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.AllowPush.IsUnknown() {
		return
	}
	pushOnly := map[string]bool{"branches": !m.Branches.IsNull(), "protected_branches": !m.ProtectedBranches.IsNull(), "tags": !m.Tags.IsNull(),
		"allow_branch_delete": m.AllowBranchDelete.ValueBool(), "allow_force_push": m.AllowForcePush.ValueBool()}
	for name, set := range pushOnly {
		if set && !m.AllowPush.ValueBool() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Push rule without allow_push", name+" only applies when allow_push is true.")
		}
	}
	if m.AllowPush.ValueBool() && m.Branches.IsNull() && m.Tags.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("branches"), "Nothing to push",
			"With allow_push, set branches or tags: agents may only push refs those patterns allow.")
	}
}

func (m *gitProfileModel) fill(ro *client.Role) {
	m.ID = types.StringValue(ro.ID)
	m.ServerID = types.StringValue(ro.ServerID)
	m.Alias = types.StringValue(ro.Alias)
	m.Description = types.StringValue(ro.Description)
	m.RemoteUser = types.StringValue(ro.RemoteUser)
	m.AllowPush = types.BoolValue(slices.Contains(ro.Capabilities, "git-write"))
	m.Repositories, m.Branches, m.ProtectedBranches, m.Tags = setOf(nil), types.SetNull(types.StringType), types.SetNull(types.StringType), types.SetNull(types.StringType)
	m.AllowBranchDelete, m.AllowForcePush = types.BoolValue(false), types.BoolValue(false)
	if ro.Git != nil {
		m.Repositories = setOf(ro.Git.Repos)
		if p := ro.Git.Push; p != nil {
			m.Branches, m.ProtectedBranches, m.Tags = optSetOf(p.Branches), optSetOf(p.ProtectedBranches), optSetOf(p.Tags)
			m.AllowBranchDelete, m.AllowForcePush = types.BoolValue(p.AllowDelete), types.BoolValue(p.AllowForcePush)
		}
	}
	m.ApprovalsRequired = types.Int64Value(ro.ApprovalsRequired)
	m.DefaultDuration = durationOf(m.DefaultDuration, ro.DefaultDuration)
	m.MaxDuration = durationOf(m.MaxDuration, ro.MaxDuration)
	m.Labels = mapOf(ro.Labels)
	m.Enabled = types.BoolValue(ro.Enabled)
}

func (m gitProfileModel) input(ctx context.Context, d *diag.Diagnostics) client.RoleInput {
	caps := []string{"git-read"}
	git := &client.GitRules{Repos: stringsOf(ctx, m.Repositories, d)}
	if m.AllowPush.ValueBool() {
		caps = append(caps, "git-write")
		git.Push = &client.PushRule{Branches: stringsOf(ctx, m.Branches, d), ProtectedBranches: stringsOf(ctx, m.ProtectedBranches, d),
			Tags: stringsOf(ctx, m.Tags, d), AllowDelete: m.AllowBranchDelete.ValueBool(), AllowForcePush: m.AllowForcePush.ValueBool()}
	}
	in := client.RoleInput{Alias: m.Alias.ValueString(), Description: m.Description.ValueString(), Capabilities: caps, Git: git,
		DefaultDuration: seconds(m.DefaultDuration), MaxDuration: seconds(m.MaxDuration), ApprovalsRequired: m.ApprovalsRequired.ValueInt64(),
		Labels: stringMapOf(ctx, m.Labels, d)}
	if !m.RemoteUser.IsUnknown() && !m.RemoteUser.IsNull() {
		in.RemoteUser = m.RemoteUser.ValueString()
	}
	return in
}

func (r *gitProfileResource) crud() roleCRUD[gitProfileModel] {
	return roleCRUD[gitProfileModel]{client: r.client, noun: "git access profile", kind: "git",
		input: func(ctx context.Context, m gitProfileModel, d *diag.Diagnostics) client.RoleInput {
			return m.input(ctx, d)
		},
		fill: func(m *gitProfileModel, ro *client.Role) { m.fill(ro) },
		ids:  func(m *gitProfileModel) (types.String, types.String) { return m.ID, m.ServerID },
		on:   func(m *gitProfileModel) bool { return m.Enabled.ValueBool() }}
}

func (r *gitProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.crud().create(ctx, req, resp)
}

func (r *gitProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.crud().read(ctx, req, resp)
}

func (r *gitProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.crud().update(ctx, req, resp)
}

func (r *gitProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.crud().delete(ctx, req, resp)
}

func (r *gitProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
