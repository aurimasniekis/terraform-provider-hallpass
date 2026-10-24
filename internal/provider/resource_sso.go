package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// ---- hallpass_oidc_provider

var _ resource.ResourceWithImportState = (*oidcProviderResource)(nil)

type oidcProviderResource struct{ baseResource }

// NewOIDCProviderResource returns the hallpass_oidc_provider resource.
func NewOIDCProviderResource() resource.Resource { return &oidcProviderResource{} }

type jitModel struct {
	EmailDomains  types.Set `tfsdk:"email_domains"`
	Tenants       types.Set `tfsdk:"tenants"`
	HostedDomains types.Set `tfsdk:"hosted_domains"`
	Groups        types.Set `tfsdk:"groups"`
}

type oidcProviderModel struct {
	ID                        types.String `tfsdk:"id"`
	Slug                      types.String `tfsdk:"slug"`
	DisplayName               types.String `tfsdk:"display_name"`
	Issuer                    types.String `tfsdk:"issuer"`
	ClientID                  types.String `tfsdk:"client_id"`
	ClientSecret              types.String `tfsdk:"client_secret"`
	Scopes                    types.List   `tfsdk:"scopes"`
	GroupsClaim               types.String `tfsdk:"groups_claim"`
	Provisioning              types.String `tfsdk:"provisioning"`
	JIT                       *jitModel    `tfsdk:"jit"`
	AllowPrivateNetwork       types.Bool   `tfsdk:"allow_private_network"`
	AllowCrossOriginEndpoints types.Bool   `tfsdk:"allow_cross_origin_endpoints"`
	CABundlePEM               types.String `tfsdk:"ca_bundle_pem"`
	StepUpFallback            types.String `tfsdk:"stepup_fallback"`
	ACRValues                 types.List   `tfsdk:"acr_values"`
	EndSessionEnabled         types.Bool   `tfsdk:"end_session_enabled"`
	Enabled                   types.Bool   `tfsdk:"enabled"`
	RedirectURI               types.String `tfsdk:"redirect_uri"`
}

func (r *oidcProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oidc_provider"
}

func optionalComputedList(desc string) schema.ListAttribute {
	return schema.ListAttribute{MarkdownDescription: desc, ElementType: types.StringType, Optional: true, Computed: true,
		PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()}}
}

func optionalComputedString(desc string, v ...validator.String) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: desc, Optional: true, Computed: true, Validators: v,
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
}

func optionalFalse(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{MarkdownDescription: desc, Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
}

func (r *oidcProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A single sign-on (OIDC) provider for the console. Register `redirect_uri` at the provider. Map its groups " +
			"to operator roles with `hallpass_oidc_group_mapping`. Identities are matched by issuer and subject, never by email. " +
			"Import with the provider ID (the client secret is not imported; set it again).",
		Attributes: map[string]schema.Attribute{
			"id":           idAttribute("Provider ID (`oidc_…`)."),
			"slug":         schema.StringAttribute{MarkdownDescription: "Short name used in sign-in URLs.", Required: true, Validators: nameValidators()},
			"display_name": schema.StringAttribute{MarkdownDescription: "Name on the sign-in button.", Required: true},
			"issuer":       schema.StringAttribute{MarkdownDescription: "Issuer URL (exact, as in the discovery document).", Required: true},
			"client_id":    schema.StringAttribute{MarkdownDescription: "OAuth client ID.", Required: true},
			"client_secret": schema.StringAttribute{MarkdownDescription: "OAuth client secret (write-only in HallPass; kept in state). " +
				"Omit for public clients.", Optional: true, Sensitive: true},
			"scopes":       optionalComputedList("Scopes to request (HallPass default when unset)."),
			"groups_claim": optionalComputedString("ID token claim that lists the user's groups."),
			"provisioning": optionalComputedString("`preprovisioned` (operators must exist) or `jit` (created at first sign-in, limited by `jit`).",
				stringvalidator.OneOf("preprovisioned", "jit")),
			"jit": schema.SingleNestedAttribute{
				MarkdownDescription: "Who may be created at first sign-in (`provisioning = \"jit\"`); at least one restriction is required.",
				Optional:            true,
				Validators:          []validator.Object{objectvalidator.AtLeastOneOf(path.MatchRelative().AtName("email_domains"), path.MatchRelative().AtName("tenants"), path.MatchRelative().AtName("hosted_domains"), path.MatchRelative().AtName("groups"))},
				Attributes: map[string]schema.Attribute{
					"email_domains":  clauseSet("Verified email domains."),
					"tenants":        clauseSet("Microsoft Entra ID tenant IDs (`tid`)."),
					"hosted_domains": clauseSet("Google Workspace domains (`hd`)."),
					"groups":         clauseSet("Required group values (any of them)."),
				},
			},
			"allow_private_network":        optionalFalse("Allow the provider's endpoints on private or loopback addresses (self-hosted IdPs)."),
			"allow_cross_origin_endpoints": optionalFalse("Allow token and key endpoints on another origin than the issuer."),
			"ca_bundle_pem": schema.StringAttribute{MarkdownDescription: "Extra CA certificates (PEM) for the provider's TLS.", Optional: true,
				Computed: true, Default: stringdefault.StaticString("")},
			"stepup_fallback": optionalComputedString("When the provider does not report a recent sign-in: `none` or `local_totp` (ask for "+
				"the operator's HallPass TOTP).", stringvalidator.OneOf("none", "local_totp")),
			"acr_values":          optionalComputedList("ACR values to request."),
			"end_session_enabled": optionalFalse("Also sign out at the provider when signing out of HallPass."),
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether the sign-in button is offered.", Optional: true, Computed: true,
				Default: booldefault.StaticBool(true)},
			"redirect_uri": computedString("Exact redirect URI to register at the provider."),
		},
	}
}

func setOrNil(ctx context.Context, s types.Set, d *diag.Diagnostics) []string {
	if s.IsNull() || s.IsUnknown() {
		return []string{}
	}
	return stringsOf(ctx, s, d)
}

func (m oidcProviderModel) body(ctx context.Context, d *diag.Diagnostics, prior *oidcProviderModel) map[string]any {
	b := map[string]any{"slug": m.Slug.ValueString(), "display_name": m.DisplayName.ValueString(), "issuer": m.Issuer.ValueString(),
		"client_id": m.ClientID.ValueString(), "allow_private_network": m.AllowPrivateNetwork.ValueBool(),
		"allow_cross_origin_endpoints": m.AllowCrossOriginEndpoints.ValueBool(), "ca_bundle_pem": m.CABundlePEM.ValueString(),
		"end_session_enabled": m.EndSessionEnabled.ValueBool(), "enabled": m.Enabled.ValueBool()}
	if prior == nil || !m.ClientSecret.Equal(prior.ClientSecret) {
		b["client_secret"] = m.ClientSecret.ValueString() // "" removes it
	}
	for name, v := range map[string]types.String{"groups_claim": m.GroupsClaim, "provisioning": m.Provisioning, "stepup_fallback": m.StepUpFallback} {
		if !v.IsNull() && !v.IsUnknown() {
			b[name] = v.ValueString()
		}
	}
	for name, v := range map[string]types.List{"scopes": m.Scopes, "acr_values": m.ACRValues} {
		if !v.IsNull() && !v.IsUnknown() {
			var out []string
			d.Append(v.ElementsAs(ctx, &out, false)...)
			b[name] = out
		}
	}
	if m.JIT != nil {
		b["jit"] = client.JITRules{EmailDomains: setOrNil(ctx, m.JIT.EmailDomains, d), Tenants: setOrNil(ctx, m.JIT.Tenants, d),
			HostedDomains: setOrNil(ctx, m.JIT.HostedDomains, d), Groups: setOrNil(ctx, m.JIT.Groups, d)}
	}
	return b
}

func listOf(ss []string) types.List {
	vals := make([]types.String, 0, len(ss))
	for _, s := range ss {
		vals = append(vals, types.StringValue(s))
	}
	l, _ := types.ListValueFrom(context.Background(), types.StringType, vals)
	return l
}

func (m *oidcProviderModel) fill(p *client.OIDCProvider) {
	m.ID = types.StringValue(p.ID)
	m.Slug = types.StringValue(p.Slug)
	m.DisplayName = types.StringValue(p.DisplayName)
	m.Issuer = types.StringValue(p.Issuer)
	m.ClientID = types.StringValue(p.ClientID)
	m.Scopes = listOf(p.Scopes)
	m.GroupsClaim = types.StringValue(p.GroupsClaim)
	m.Provisioning = types.StringValue(p.Provisioning)
	if j := p.JIT; j != nil && (len(j.EmailDomains)+len(j.Tenants)+len(j.HostedDomains)+len(j.Groups)) > 0 {
		m.JIT = &jitModel{EmailDomains: optSetOf(j.EmailDomains), Tenants: optSetOf(j.Tenants), HostedDomains: optSetOf(j.HostedDomains),
			Groups: optSetOf(j.Groups)}
	} else {
		m.JIT = nil
	}
	m.AllowPrivateNetwork = types.BoolValue(p.AllowPrivateNetwork)
	m.AllowCrossOriginEndpoints = types.BoolValue(p.AllowCrossOriginEndpoints)
	m.CABundlePEM = types.StringValue(p.CABundlePEM)
	m.StepUpFallback = types.StringValue(p.StepUpFallback)
	m.ACRValues = listOf(p.ACRValues)
	m.EndSessionEnabled = types.BoolValue(p.EndSessionEnabled)
	m.Enabled = types.BoolValue(p.Enabled)
	m.RedirectURI = types.StringValue(p.RedirectURI)
}

func (r *oidcProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan oidcProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := plan.body(ctx, &resp.Diagnostics, nil)
	if plan.ClientSecret.IsNull() {
		delete(body, "client_secret")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.CreateOIDCProvider(ctx, body)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create OIDC provider", err)
		return
	}
	plan.fill(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, p.Version)...)
}

func (r *oidcProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state oidcProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.GetOIDCProvider(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read OIDC provider", err)
		return
	}
	state.fill(p)
	if !p.HasClientSecret {
		state.ClientSecret = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, p.Version)...)
}

func (r *oidcProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state oidcProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := plan.body(ctx, &resp.Diagnostics, &state)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.UpdateOIDCProvider(ctx, state.ID.ValueString(), loadVersion(ctx, req.Private), body)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update OIDC provider", err)
		return
	}
	plan.fill(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, p.Version)...)
}

func (r *oidcProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state oidcProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteOIDCProvider(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete OIDC provider", err)
	}
}

func (r *oidcProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- hallpass_oidc_group_mapping

var (
	_ resource.ResourceWithImportState      = (*oidcMappingResource)(nil)
	_ resource.ResourceWithConfigValidators = (*oidcMappingResource)(nil)
)

type oidcMappingResource struct{ baseResource }

// NewOIDCGroupMappingResource returns the hallpass_oidc_group_mapping resource.
func NewOIDCGroupMappingResource() resource.Resource { return &oidcMappingResource{} }

type oidcMappingModel struct {
	ID         types.String `tfsdk:"id"`
	ProviderID types.String `tfsdk:"provider_id"`
	GroupValue types.String `tfsdk:"group_value"`
	Role       types.String `tfsdk:"role"`
	GroupID    types.String `tfsdk:"group_id"`
}

func (r *oidcMappingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oidc_group_mapping"
}

func replaceString(desc string, required bool, v ...validator.String) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: desc + " Changing it forces a new resource.", Required: required, Optional: !required,
		Validators: v, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func (r *oidcMappingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Maps a group from the provider's groups claim to an operator role, or to an operator group (for approver " +
			"rules). Operators get it at their next sign-in. Import with `<provider_id>/<mapping_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("Mapping ID (`ogm_…`)."),
			"provider_id": parentAttribute("OIDC provider ID (`oidc_…`).", "oidc"),
			"group_value": replaceString("Group value as it appears in the claim.", true, stringvalidator.LengthBetween(1, 256)),
			"role": replaceString("Operator role: `administrator`, `approver`, `auditor` or `viewer`.", false,
				stringvalidator.OneOf("administrator", "approver", "auditor", "viewer")),
			"group_id": replaceString("Operator group ID (`grp_…`).", false, idValidator("grp")),
		},
	}
}

func (r *oidcMappingResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{resourcevalidator.ExactlyOneOf(path.MatchRoot("role"), path.MatchRoot("group_id"))}
}

func (r *oidcMappingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan oidcMappingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m, err := r.client.AddOIDCMapping(ctx, plan.ProviderID.ValueString(), plan.GroupValue.ValueString(), plan.Role.ValueString(), plan.GroupID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot add group mapping", err)
		return
	}
	plan.ID = types.StringValue(m.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *oidcMappingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state oidcMappingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m, err := r.client.GetOIDCMapping(ctx, state.ProviderID.ValueString(), state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read group mapping", err)
		return
	}
	state.GroupValue, state.Role, state.GroupID = types.StringValue(m.GroupValue), optString(m.Role), optString(m.GroupID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *oidcMappingResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *oidcMappingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state oidcMappingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteOIDCMapping(ctx, state.ProviderID.ValueString(), state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete group mapping", err)
	}
}

func (r *oidcMappingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitID(req.ID, 2, "<provider_id>/<mapping_id>")
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("provider_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[1])...)
}
