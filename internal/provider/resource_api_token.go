package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var _ resource.ResourceWithValidateConfig = (*apiTokenResource)(nil)

type apiTokenResource struct{ baseResource }

// NewAPITokenResource returns the hallpass_api_token resource.
func NewAPITokenResource() resource.Resource { return &apiTokenResource{} }

type apiTokenModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Role          types.String `tfsdk:"role"`
	ExpiresInDays types.Int64  `tfsdk:"expires_in_days"`
	NeverExpires  types.Bool   `tfsdk:"never_expires"`
	Triggers      types.Map    `tfsdk:"triggers"`
	Token         types.String `tfsdk:"token"`
	Hint          types.String `tfsdk:"hint"`
	OperatorID    types.String `tfsdk:"operator_id"`
	CreatedAt     types.String `tfsdk:"created_at"`
	ExpiresAt     types.String `tfsdk:"expires_at"`
}

func (r *apiTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_token"
}

func (r *apiTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An API token issued by the provider's own (Administrator) token, for example a read-only Auditor " +
			"token for an integration. It acts for the same operator as the provider's token, with the role given here, " +
			"and is revoked together with the provider's token. `token` is known only to the Terraform run that creates " +
			"it and is kept in state (sensitive): store it in your secret manager from the same configuration. Destroying " +
			"the resource revokes the token. A token that expired or was revoked outside Terraform is created again on the " +
			"next apply. To rotate, change `triggers` (with `create_before_destroy`, the old token stays valid until the new " +
			"one is stored). Every argument forces a new token. Cannot be imported, because HallPass shows a token only once.",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute("API token ID (`atk_…`)."),
			"name": schema.StringAttribute{
				MarkdownDescription: "Name, after what uses the token (1-100 characters).",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 100)},
			},
			"role": schema.StringAttribute{
				MarkdownDescription: "Role of the token: `administrator`, `approver`, `auditor` or `viewer`. Pick the least the " +
					"integration needs. Approvals and recordings stay console-only whatever the role.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.OneOf("administrator", "approver", "auditor", "viewer")},
			},
			"expires_in_days": schema.Int64Attribute{
				MarkdownDescription: "Days until the token expires (1-366). Required unless `never_expires` is set.",
				Optional:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
				Validators:          []validator.Int64{int64validator.Between(1, 366)},
			},
			"never_expires": schema.BoolAttribute{
				MarkdownDescription: "Issue a token without expiry. It still stops when revoked or when the operator it acts for " +
					"is disabled or stops being an administrator. Defaults to `false`.",
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"triggers": schema.MapAttribute{
				MarkdownDescription: "Arbitrary values; changing any of them issues a new token (rotation).",
				ElementType:         types.StringType, Optional: true,
				PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()},
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The token (`hallpass_at_…`), for the integration's `Authorization: Bearer` header.",
				Computed:            true, Sensitive: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"hint":        computedString("Last four characters of the token, as the console shows it."),
			"operator_id": computedString("The operator the token acts for (the one behind the provider's token)."),
			"created_at":  computedString("When the token was issued (RFC 3339)."),
			"expires_at":  computedString("When the token expires (RFC 3339); empty when it never expires."),
		},
	}
}

func (r *apiTokenResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m apiTokenModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.ExpiresInDays.IsUnknown() || m.NeverExpires.IsUnknown() {
		return
	}
	never := m.NeverExpires.ValueBool()
	switch {
	case never && !m.ExpiresInDays.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("expires_in_days"), "Conflicting expiry", "Omit expires_in_days when never_expires is true.")
	case !never && m.ExpiresInDays.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("expires_in_days"), "Missing expiry", "Set expires_in_days (1-366), or never_expires = true.")
	}
}

func (m *apiTokenModel) fill(t *client.APIToken) {
	m.ID = types.StringValue(t.ID)
	m.Hint = types.StringValue(t.Hint)
	m.OperatorID = types.StringValue(t.OperatorID)
	m.CreatedAt = types.StringValue(t.CreatedAt)
	m.ExpiresAt = types.StringValue(t.ExpiresAt)
}

func (r *apiTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.APITokenInput{Name: plan.Name.ValueString(), Role: plan.Role.ValueString(), NeverExpires: plan.NeverExpires.ValueBool()}
	if !in.NeverExpires {
		in.ExpiresInDays = plan.ExpiresInDays.ValueInt64()
	}
	res, err := r.client.CreateAPIToken(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot issue API token (the provider needs an Administrator token)", err)
		return
	}
	plan.Token = types.StringValue(res.Token)
	plan.fill(&res.APIToken)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *apiTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.GetAPIToken(ctx, state.ID.ValueString())
	if client.IsNotFound(err) || (err == nil && (t.RevokedAt != "" || expired(t.ExpiresAt))) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read API token", err)
		return
	}
	state.fill(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// expired reports whether an RFC 3339 expiry has passed ("" never expires).
func expired(at string) bool {
	if at == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, at)
	return err == nil && !time.Now().Before(t)
}

func (r *apiTokenResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every argument forces a new token.
}

func (r *apiTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeAPIToken(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot revoke API token", err)
	}
}
