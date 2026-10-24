package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// ---- hallpass_policy_rule

var (
	_ resource.ResourceWithImportState    = (*policyRuleResource)(nil)
	_ resource.ResourceWithValidateConfig = (*policyRuleResource)(nil)
)

type policyRuleResource struct{ baseResource }

// NewPolicyRuleResource returns the hallpass_policy_rule resource.
func NewPolicyRuleResource() resource.Resource { return &policyRuleResource{} }

type policyRuleModel struct {
	ID              types.String   `tfsdk:"id"`
	Name            types.String   `tfsdk:"name"`
	Description     types.String   `tfsdk:"description"`
	Effect          types.String   `tfsdk:"effect"`
	Level           types.String   `tfsdk:"level"`
	Subjects        *subjectsModel `tfsdk:"subjects"`
	Targets         *targetsModel  `tfsdk:"targets"`
	Roles           *rolesModel    `tfsdk:"roles"`
	MaxDuration     types.String   `tfsdk:"max_duration"`
	AutoMaxDuration types.String   `tfsdk:"auto_max_duration"`
	RequireReason   types.Bool     `tfsdk:"require_reason"`
	Enabled         types.Bool     `tfsdk:"enabled"`
}

func (r *policyRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_rule"
}

func optionalDuration(desc string) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: desc + " A duration such as `30m` or `4h`.", Optional: true,
		Validators: []validator.String{durationValidator()}}
}

func (r *policyRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An access rule. HallPass denies by default; rules allow agents (`subjects`) to see, request or be " +
			"approved automatically for roles (`roles`) on servers and git remotes (`targets`), and `deny` rules override every " +
			"allow. Import with the rule ID.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("Rule ID (`pol_…`)."),
			"name":        schema.StringAttribute{MarkdownDescription: "Name.", Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 128)}},
			"description": descriptionAttribute(2000),
			"effect": schema.StringAttribute{MarkdownDescription: "`allow` or `deny`.", Required: true,
				Validators: []validator.String{stringvalidator.OneOf("allow", "deny")}},
			"level": schema.StringAttribute{
				MarkdownDescription: "For `allow`: `visible` (listed only), `requestable` (a person approves) or `auto_approve` " +
					"(approved automatically up to `auto_max_duration`). Not used with `deny`.",
				Optional: true, Validators: []validator.String{stringvalidator.OneOf("visible", "requestable", "auto_approve")}},
			"subjects":          subjectsAttribute(),
			"targets":           targetsAttribute("Which servers and git remotes.", true),
			"roles":             rolesAttribute(),
			"max_duration":      optionalDuration("Longest access this rule allows (the role's maximum applies too)."),
			"auto_max_duration": optionalDuration("Longest access approved automatically (`auto_approve` only)."),
			"require_reason": schema.BoolAttribute{MarkdownDescription: "Whether agents must give a reason.", Optional: true, Computed: true,
				Default: booldefault.StaticBool(true)},
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether the rule applies.", Optional: true, Computed: true,
				Default: booldefault.StaticBool(true)},
		},
	}
}

func (r *policyRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m policyRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Effect.IsUnknown() || m.Level.IsUnknown() {
		return
	}
	switch {
	case m.Effect.ValueString() == "allow" && m.Level.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("level"), "Missing level", "An allow rule needs a level.")
	case m.Effect.ValueString() == "deny" && !m.Level.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("level"), "Level on a deny rule", "Deny rules have no level.")
	case !m.AutoMaxDuration.IsNull() && m.Level.ValueString() != "auto_approve":
		resp.Diagnostics.AddAttributeError(path.Root("auto_max_duration"), "Not an auto-approve rule",
			"auto_max_duration only applies with level = \"auto_approve\".")
	}
}

func (m policyRuleModel) toAPI(ctx context.Context, d *diag.Diagnostics) client.PolicyRule {
	return client.PolicyRule{Name: m.Name.ValueString(), Description: m.Description.ValueString(), Effect: m.Effect.ValueString(),
		Level: m.Level.ValueString(), Subjects: m.Subjects.toAPI(ctx, d), Targets: m.Targets.toAPI(ctx, d), Roles: m.Roles.toAPI(ctx, d),
		MaxDuration: seconds(m.MaxDuration), AutoMaxDuration: seconds(m.AutoMaxDuration), RequireReason: ptr(m.RequireReason.ValueBool()),
		Enabled: m.Enabled.ValueBool()}
}

func (m *policyRuleModel) fill(p *client.PolicyRule) {
	m.ID = types.StringValue(p.ID)
	m.Name = types.StringValue(p.Name)
	m.Description = types.StringValue(p.Description)
	m.Effect = types.StringValue(p.Effect)
	m.Level = optString(p.Level)
	m.Subjects, m.Targets, m.Roles = subjectsFrom(p.Subjects), targetsFrom(p.Targets), rolesFrom(p.Roles)
	m.MaxDuration = durationOf(m.MaxDuration, p.MaxDuration)
	m.AutoMaxDuration = durationOf(m.AutoMaxDuration, p.AutoMaxDuration)
	m.RequireReason = types.BoolValue(p.RequireReason == nil || *p.RequireReason)
	m.Enabled = types.BoolValue(p.Enabled)
}

func (r *policyRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.CreatePolicyRule(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create policy rule", err)
		return
	}
	plan.fill(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, p.Version)...)
}

func (r *policyRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.GetPolicyRule(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read policy rule", err)
		return
	}
	state.fill(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, p.Version)...)
}

func (r *policyRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state policyRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.UpdatePolicyRule(ctx, state.ID.ValueString(), loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update policy rule", err)
		return
	}
	plan.fill(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, p.Version)...)
}

func (r *policyRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeletePolicyRule(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete policy rule", err)
	}
}

func (r *policyRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- hallpass_approver_rule

var _ resource.ResourceWithImportState = (*approverRuleResource)(nil)

type approverRuleResource struct{ baseResource }

// NewApproverRuleResource returns the hallpass_approver_rule resource.
func NewApproverRuleResource() resource.Resource { return &approverRuleResource{} }

type approverRuleModel struct {
	ID          types.String    `tfsdk:"id"`
	Name        types.String    `tfsdk:"name"`
	Description types.String    `tfsdk:"description"`
	Operators   *operatorsModel `tfsdk:"operators"`
	Targets     *targetsModel   `tfsdk:"targets"`
	Roles       *rolesModel     `tfsdk:"roles"`
	MaxDuration types.String    `tfsdk:"max_duration"`
	Enabled     types.Bool      `tfsdk:"enabled"`
}

func (r *approverRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_approver_rule"
}

func (r *approverRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Says which operators may approve which requests (in the console, Slack or Telegram). Operators also " +
			"need the approver or administrator role. Import with the rule ID.",
		Attributes: map[string]schema.Attribute{
			"id":           idAttribute("Rule ID (`apr_…`)."),
			"name":         schema.StringAttribute{MarkdownDescription: "Name.", Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 128)}},
			"description":  descriptionAttribute(2000),
			"operators":    operatorsAttribute(),
			"targets":      targetsAttribute("Requests for which servers and git remotes.", true),
			"roles":        rolesAttribute(),
			"max_duration": optionalDuration("Longest access these operators may approve."),
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether the rule applies.", Optional: true, Computed: true,
				Default: booldefault.StaticBool(true)},
		},
	}
}

func (m approverRuleModel) toAPI(ctx context.Context, d *diag.Diagnostics) client.ApproverRule {
	return client.ApproverRule{Name: m.Name.ValueString(), Description: m.Description.ValueString(), Operators: m.Operators.toAPI(ctx, d),
		Targets: m.Targets.toAPI(ctx, d), Roles: m.Roles.toAPI(ctx, d), MaxDuration: seconds(m.MaxDuration), Enabled: m.Enabled.ValueBool()}
}

func (m *approverRuleModel) fill(a *client.ApproverRule) {
	m.ID = types.StringValue(a.ID)
	m.Name = types.StringValue(a.Name)
	m.Description = types.StringValue(a.Description)
	m.Operators, m.Targets, m.Roles = operatorsFrom(a.Operators), targetsFrom(a.Targets), rolesFrom(a.Roles)
	m.MaxDuration = durationOf(m.MaxDuration, a.MaxDuration)
	m.Enabled = types.BoolValue(a.Enabled)
}

func (r *approverRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan approverRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.CreateApproverRule(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create approver rule", err)
		return
	}
	plan.fill(a)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, a.Version)...)
}

func (r *approverRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state approverRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.GetApproverRule(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read approver rule", err)
		return
	}
	state.fill(a)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, a.Version)...)
}

func (r *approverRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state approverRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.UpdateApproverRule(ctx, state.ID.ValueString(), loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update approver rule", err)
		return
	}
	plan.fill(a)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, a.Version)...)
}

func (r *approverRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state approverRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteApproverRule(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete approver rule", err)
	}
}

func (r *approverRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
