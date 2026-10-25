package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// Installation-wide settings are singletons: creating the resource sets them, destroying it restores the default.

// ---- hallpass_self_approval

type selfApprovalResource struct{ baseResource }

// NewSelfApprovalResource returns the hallpass_self_approval resource.
func NewSelfApprovalResource() resource.Resource { return &selfApprovalResource{} }

type selfApprovalModel struct {
	ID                   types.String `tfsdk:"id"`
	ProhibitSelfApproval types.Bool   `tfsdk:"prohibit_self_approval"`
}

func (r *selfApprovalResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_self_approval"
}

func (r *selfApprovalResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Whether an agent's owners may approve that agent's requests. Installation-wide: declare it at most " +
			"once. Destroying it restores the default (prohibited).",
		Attributes: map[string]schema.Attribute{
			"id":                     idAttribute("Always `self-approval`."),
			"prohibit_self_approval": schema.BoolAttribute{MarkdownDescription: "Refuse approvals by the agent's own owners.", Required: true},
		},
	}
}

func (r *selfApprovalResource) set(ctx context.Context, m *selfApprovalModel) error {
	out, err := r.client.SetSelfApproval(ctx, client.SelfApproval{ProhibitSelfApproval: m.ProhibitSelfApproval.ValueBool()})
	if err != nil {
		return err
	}
	m.ID, m.ProhibitSelfApproval = types.StringValue("self-approval"), types.BoolValue(out.ProhibitSelfApproval)
	return nil
}

func (r *selfApprovalResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan selfApprovalModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.set(ctx, &plan); err != nil {
		apiError(&resp.Diagnostics, "Cannot set self-approval", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *selfApprovalResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state selfApprovalModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetSelfApproval(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read self-approval", err)
		return
	}
	state.ProhibitSelfApproval = types.BoolValue(out.ProhibitSelfApproval)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *selfApprovalResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan selfApprovalModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.set(ctx, &plan); err != nil {
		apiError(&resp.Diagnostics, "Cannot set self-approval", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *selfApprovalResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if _, err := r.client.SetSelfApproval(ctx, client.SelfApproval{ProhibitSelfApproval: true}); err != nil {
		apiError(&resp.Diagnostics, "Cannot restore the self-approval default", err)
	}
}

// ---- hallpass_auth_settings

type authSettingsResource struct{ baseResource }

// NewAuthSettingsResource returns the hallpass_auth_settings resource.
func NewAuthSettingsResource() resource.Resource { return &authSettingsResource{} }

type authSettingsModel struct {
	ID                 types.String `tfsdk:"id"`
	LocalLoginDisabled types.Bool   `tfsdk:"local_login_disabled"`
	DirectProvider     types.String `tfsdk:"direct_provider"`
}

func (r *authSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_settings"
}

func (r *authSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Console sign-in settings. Installation-wide: declare it at most once. HallPass refuses to turn off " +
			"password sign-in until an administrator has completed a single sign-on test login, so a broken SSO setup cannot lock " +
			"everyone out. Destroying it turns password sign-in back on and shows the sign-in options again.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute("Always `auth`."),
			"local_login_disabled": schema.BoolAttribute{MarkdownDescription: "Turn off password sign-in (single sign-on only).",
				Required: true},
			"direct_provider": schema.StringAttribute{MarkdownDescription: "Slug of an enabled single sign-on provider the sign-in " +
				"page goes to directly instead of showing the sign-in options; `\"\"` shows them. `/login/password` always shows every " +
				"sign-in method. Left out, the setting is not managed. Needs HallPass 0.3.0 or later.",
				Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (r *authSettingsResource) set(ctx context.Context, m *authSettingsModel) error {
	in := client.AuthSettings{LocalLoginDisabled: m.LocalLoginDisabled.ValueBool()}
	if !m.DirectProvider.IsNull() && !m.DirectProvider.IsUnknown() {
		in.DirectProvider = m.DirectProvider.ValueStringPointer()
	}
	out, err := r.client.SetAuthSettings(ctx, in)
	if err != nil {
		return err
	}
	m.ID, m.LocalLoginDisabled, m.DirectProvider = types.StringValue("auth"), types.BoolValue(out.LocalLoginDisabled), directProvider(out)
	return nil
}

// directProvider is the state value: "" when none is set or the server predates the setting.
func directProvider(out *client.AuthSettings) types.String {
	if out.DirectProvider == nil {
		return types.StringValue("")
	}
	return types.StringValue(*out.DirectProvider)
}

func (r *authSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan authSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.set(ctx, &plan); err != nil {
		apiError(&resp.Diagnostics, "Cannot change sign-in settings", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *authSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state authSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetAuthSettings(ctx)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read sign-in settings", err)
		return
	}
	state.LocalLoginDisabled, state.DirectProvider = types.BoolValue(out.LocalLoginDisabled), directProvider(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *authSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan authSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.set(ctx, &plan); err != nil {
		apiError(&resp.Diagnostics, "Cannot change sign-in settings", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *authSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state authSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.AuthSettings{LocalLoginDisabled: false}
	if state.DirectProvider.ValueString() != "" {
		// Only sent when set, so destroying works against servers that predate the setting.
		in.DirectProvider = new(string)
	}
	if _, err := r.client.SetAuthSettings(ctx, in); err != nil {
		apiError(&resp.Diagnostics, "Cannot turn password sign-in back on", err)
	}
}
