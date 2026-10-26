package provider

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var operatorRoles = []string{"administrator", "approver", "auditor", "viewer"}

// ---- hallpass_operator

var _ resource.ResourceWithImportState = (*operatorResource)(nil)

type operatorResource struct{ baseResource }

// NewOperatorResource returns the hallpass_operator resource.
func NewOperatorResource() resource.Resource { return &operatorResource{} }

type operatorModel struct {
	ID          types.String `tfsdk:"id"`
	Email       types.String `tfsdk:"email"`
	DisplayName types.String `tfsdk:"display_name"`
	Roles       types.Set    `tfsdk:"roles"`
	Groups      types.Set    `tfsdk:"groups"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	SSORoles    types.Set    `tfsdk:"sso_roles"`
	HasPassword types.Bool   `tfsdk:"has_password"`
}

func (r *operatorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_operator"
}

func (r *operatorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An operator: a person who signs in to the HallPass console. It is created without a password; link a " +
			"single sign-on identity with `hallpass_operator_identity`, or send a password-reset link from the console. " +
			"`roles` are the manually assigned roles; roles mapped from single sign-on groups are managed by the identity " +
			"provider and shown in `sso_roles`. The provider's token cannot change the operator it acts for. HallPass never " +
			"deletes operators (the audit log names them), so destroying the resource **disables** the operator and removes " +
			"its manual roles; to manage it again, import it. Email and display name cannot be changed through the API. " +
			"Import with the operator ID.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute("Operator ID (`opr_…`)."),
			"email": schema.StringAttribute{
				MarkdownDescription: "Email address (unique among operators). It is not used to match single sign-on accounts. " +
					"Changing it forces a new operator.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name": schema.StringAttribute{
				MarkdownDescription: "Name shown in the console and audit log (at most 128 bytes). Changing it forces a new operator.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 128)},
			},
			"roles": schema.SetAttribute{
				MarkdownDescription: "Manually assigned roles: `administrator`, `approver`, `auditor`, `viewer`. Defaults to none.",
				ElementType:         types.StringType, Optional: true, Computed: true,
				Default:    setdefault.StaticValue(setOf(nil)),
				Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.OneOf(operatorRoles...))},
			},
			"groups": schema.SetAttribute{
				MarkdownDescription: "Operator groups, used by approver rules. Defaults to none.",
				ElementType:         types.StringType, Optional: true, Computed: true,
				Default:    setdefault.StaticValue(setOf(nil)),
				Validators: []validator.Set{setvalidator.ValueStringsAre(nameValidators()...)},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the operator may sign in. Disabling ends their sessions and stops their API tokens. " +
					"Defaults to `true`.",
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
			},
			"sso_roles": schema.SetAttribute{
				MarkdownDescription: "Roles mapped from single sign-on groups (read-only).",
				ElementType:         types.StringType, Computed: true,
			},
			"has_password": schema.BoolAttribute{MarkdownDescription: "Whether the operator has set a password.", Computed: true},
		},
	}
}

func (m *operatorModel) fill(o *client.OperatorDetail) {
	m.ID = types.StringValue(o.ID)
	m.Email = types.StringValue(o.Email)
	m.DisplayName = types.StringValue(o.DisplayName)
	m.Roles = setOf(o.ManualRoles())
	m.Groups = setOf(o.Groups)
	m.Enabled = types.BoolValue(o.Enabled)
	var sso []string
	for _, a := range o.RoleAssignments {
		if a.Source != "manual" && !slices.Contains(sso, a.Role) {
			sso = append(sso, a.Role)
		}
	}
	m.SSORoles = setOf(sso)
	m.HasPassword = types.BoolValue(o.HasPassword)
}

func (r *operatorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan operatorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	roles, groups := stringsOf(ctx, plan.Roles, &resp.Diagnostics), stringsOf(ctx, plan.Groups, &resp.Diagnostics)
	o, err := r.client.CreateOperator(ctx, client.OperatorCreate{Email: plan.Email.ValueString(), DisplayName: plan.DisplayName.ValueString(), Roles: roles})
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create operator", err)
		return
	}
	// Save the operator first so a failure below leaves it in state, not orphaned.
	plan.ID = types.StringValue(o.ID)
	patchIn := client.OperatorPatch{}
	if len(groups) > 0 {
		patchIn.Groups = &groups
	}
	if !plan.Enabled.ValueBool() {
		patchIn.Enabled = ptr(false)
	}
	if patchIn.Groups != nil || patchIn.Enabled != nil {
		if o, err = r.client.UpdateOperator(ctx, o.ID, patchIn); err != nil {
			plan.fill(o)
			resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
			apiError(&resp.Diagnostics, "Cannot set operator groups or enabled state", err)
			return
		}
	}
	plan.fill(o)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *operatorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state operatorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	o, err := r.client.GetOperator(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read operator", err)
		return
	}
	state.fill(o)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *operatorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state operatorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.OperatorPatch{}
	if roles := stringsOf(ctx, plan.Roles, &resp.Diagnostics); !slices.Equal(roles, stringsOf(ctx, state.Roles, &resp.Diagnostics)) {
		in.Roles = &roles
	}
	if groups := stringsOf(ctx, plan.Groups, &resp.Diagnostics); !slices.Equal(groups, stringsOf(ctx, state.Groups, &resp.Diagnostics)) {
		in.Groups = &groups
	}
	if !plan.Enabled.Equal(state.Enabled) {
		in.Enabled = ptr(plan.Enabled.ValueBool())
	}
	o, err := r.client.UpdateOperator(ctx, state.ID.ValueString(), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update operator", err)
		return
	}
	plan.fill(o)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *operatorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state operatorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.UpdateOperator(ctx, state.ID.ValueString(), client.OperatorPatch{Roles: &[]string{}, Enabled: ptr(false)})
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot disable operator", err)
	}
}

func (r *operatorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- hallpass_operator_identity

var _ resource.ResourceWithImportState = (*operatorIdentityResource)(nil)

type operatorIdentityResource struct{ baseResource }

// NewOperatorIdentityResource returns the hallpass_operator_identity resource.
func NewOperatorIdentityResource() resource.Resource { return &operatorIdentityResource{} }

type operatorIdentityModel struct {
	ID         types.String `tfsdk:"id"`
	OperatorID types.String `tfsdk:"operator_id"`
	ProviderID types.String `tfsdk:"provider_id"`
	Subject    types.String `tfsdk:"subject"`
	Issuer     types.String `tfsdk:"issuer"`
}

func (r *operatorIdentityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_operator_identity"
}

func (r *operatorIdentityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Links a single sign-on identity (the provider's `sub` claim) to an operator, so that person signs in " +
			"with that provider as the operator. HallPass matches single sign-on accounts only by issuer and subject, never by " +
			"email. **Whoever controls this identity at the provider signs in as the operator**, so take the subject from the " +
			"provider, not from the person. Destroying it unlinks the identity and ends the operator's single sign-on sessions. " +
			"Import with `<operator_id>/<provider_id>/<subject>`.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("`<operator_id>/<issuer>/<subject>`."),
			"operator_id": parentAttribute("Operator ID (`opr_…`).", "opr"),
			"provider_id": parentAttribute("Single sign-on provider ID (`oidc_…`, from `hallpass_oidc_provider`).", "oidc"),
			"subject": schema.StringAttribute{
				MarkdownDescription: "The identity's `sub` claim at the provider. Changing it forces a new link.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 255)},
			},
			"issuer": computedString("The provider's issuer URL."),
		},
	}
}

func (r *operatorIdentityResource) find(ctx context.Context, m *operatorIdentityModel) (*client.OperatorIdentity, error) {
	items, err := r.client.ListOperatorIdentities(ctx, m.OperatorID.ValueString())
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.ProviderID == m.ProviderID.ValueString() && it.Subject == m.Subject.ValueString() {
			return &it, nil
		}
	}
	return nil, nil
}

func (r *operatorIdentityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan operatorIdentityModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.LinkOperatorIdentity(ctx, plan.OperatorID.ValueString(), plan.ProviderID.ValueString(), plan.Subject.ValueString()); err != nil {
		apiError(&resp.Diagnostics, "Cannot link single sign-on identity", err)
		return
	}
	it, err := r.find(ctx, &plan)
	if err != nil || it == nil {
		resp.Diagnostics.AddError("Cannot read linked identity", fmt.Sprintf("the identity was linked but cannot be read back: %v", err))
		return
	}
	plan.Issuer = types.StringValue(it.Issuer)
	plan.ID = types.StringValue(plan.OperatorID.ValueString() + "/" + it.Issuer + "/" + it.Subject)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *operatorIdentityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state operatorIdentityModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	it, err := r.find(ctx, &state)
	if client.IsNotFound(err) || (err == nil && it == nil) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read single sign-on identities", err)
		return
	}
	state.Issuer = types.StringValue(it.Issuer)
	state.ID = types.StringValue(state.OperatorID.ValueString() + "/" + it.Issuer + "/" + it.Subject)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *operatorIdentityResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *operatorIdentityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state operatorIdentityModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.UnlinkOperatorIdentity(ctx, state.OperatorID.ValueString(), state.Issuer.ValueString(), state.Subject.ValueString())
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot unlink single sign-on identity", err)
	}
}

func (r *operatorIdentityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitID(req.ID, 3, "<operator_id>/<provider_id>/<subject>")
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("operator_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("provider_id"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("subject"), parts[2])...)
}

// ---- hallpass_operator_chat_link

var _ resource.ResourceWithImportState = (*chatLinkResource)(nil)

type chatLinkResource struct{ baseResource }

// NewChatLinkResource returns the hallpass_operator_chat_link resource.
func NewChatLinkResource() resource.Resource { return &chatLinkResource{} }

type chatLinkModel struct {
	ID             types.String `tfsdk:"id"`
	OperatorID     types.String `tfsdk:"operator_id"`
	Platform       types.String `tfsdk:"platform"`
	Workspace      types.String `tfsdk:"workspace"`
	ProviderUserID types.String `tfsdk:"provider_user_id"`
	Display        types.String `tfsdk:"display"`
}

func (r *chatLinkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_operator_chat_link"
}

func (r *chatLinkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Links a Slack or Telegram account to an operator, so approvals from that account in chat act as the " +
			"operator (within the operator's approver rules). **Whoever controls the chat account approves as the operator**, " +
			"so take the user ID from the chat provider, not from a message. HallPass removes an operator's chat links when the " +
			"operator is disabled or their password is set or changed; the next apply links the account again. Destroying it " +
			"unlinks the account. Import with " +
			"`<operator_id>/<platform>/<workspace>/<provider_user_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("`<operator_id>/<platform>/<workspace>/<provider_user_id>`."),
			"operator_id": parentAttribute("Operator ID (`opr_…`).", "opr"),
			"platform": schema.StringAttribute{
				MarkdownDescription: "`slack` or `telegram`. Changing it forces a new link.",
				Required:            true, PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.OneOf("slack", "telegram")},
			},
			"workspace": schema.StringAttribute{
				MarkdownDescription: "Slack team ID, or the Telegram integration's workspace identifier, as the console shows it. " +
					"Changing it forces a new link.",
				Required: true, PlanModifiers: replace,
			},
			"provider_user_id": schema.StringAttribute{
				MarkdownDescription: "The chat account's user ID (Slack member ID, Telegram numeric user ID). Changing it forces a new link.",
				Required:            true, PlanModifiers: replace,
			},
			"display": schema.StringAttribute{
				MarkdownDescription: "Label shown in the console, for example `@alice`. Changing it forces a new link.",
				Optional:            true, PlanModifiers: replace,
			},
		},
	}
}

func (m *chatLinkModel) key() string {
	return m.OperatorID.ValueString() + "/" + m.Platform.ValueString() + "/" + m.Workspace.ValueString() + "/" + m.ProviderUserID.ValueString()
}

func (r *chatLinkResource) find(ctx context.Context, m *chatLinkModel) (*client.ChatLink, error) {
	items, err := r.client.ListChatLinks(ctx, m.OperatorID.ValueString())
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.Provider == m.Platform.ValueString() && it.Workspace == m.Workspace.ValueString() && it.ProviderUserID == m.ProviderUserID.ValueString() {
			return &it, nil
		}
	}
	return nil, nil
}

func (r *chatLinkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan chatLinkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.LinkChat(ctx, plan.OperatorID.ValueString(), client.ChatLink{Provider: plan.Platform.ValueString(),
		Workspace: plan.Workspace.ValueString(), ProviderUserID: plan.ProviderUserID.ValueString(), Display: plan.Display.ValueString()})
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot link chat account", err)
		return
	}
	plan.ID = types.StringValue(plan.key())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *chatLinkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state chatLinkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	it, err := r.find(ctx, &state)
	if client.IsNotFound(err) || (err == nil && it == nil) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read chat accounts", err)
		return
	}
	state.Display = optString(it.Display)
	state.ID = types.StringValue(state.key())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *chatLinkResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *chatLinkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state chatLinkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.UnlinkChat(ctx, state.OperatorID.ValueString(), state.Platform.ValueString(), state.Workspace.ValueString(), state.ProviderUserID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot unlink chat account", err)
	}
}

func (r *chatLinkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitID(req.ID, 4, "<operator_id>/<platform>/<workspace>/<provider_user_id>")
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	for i, a := range []string{"operator_id", "platform", "workspace", "provider_user_id"} {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(a), parts[i])...)
	}
}
