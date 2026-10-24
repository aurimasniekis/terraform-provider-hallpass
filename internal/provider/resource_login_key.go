package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var _ resource.ResourceWithImportState = (*loginKeyResource)(nil)

type loginKeyResource struct{ baseResource }

// NewLoginKeyResource returns the hallpass_login_key resource.
func NewLoginKeyResource() resource.Resource { return &loginKeyResource{} }

type loginKeyModel struct {
	ID                 types.String `tfsdk:"id"`
	RoleID             types.String `tfsdk:"role_id"`
	Triggers           types.Map    `tfsdk:"triggers"`
	PublicKey          types.String `tfsdk:"public_key"`
	AuthorizedKeysLine types.String `tfsdk:"authorized_keys_line"`
	Fingerprint        types.String `tfsdk:"fingerprint"`
	Algorithm          types.String `tfsdk:"algorithm"`
}

func (r *loginKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_login_key"
}

func (r *loginKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A login key HallPass generates for a role or git access profile. The private key never leaves HallPass. " +
			"Install `authorized_keys_line` on the server (or `public_key` on the git host, e.g. as a GitHub deploy key), then " +
			"activate it with `hallpass_login_key_activation`. Destroying it revokes the key. To rotate, change `triggers` " +
			"(create_before_destroy keeps the old key until the new one is active). Import with `<role_id>/<key_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":      idAttribute("Login key ID (`cred_…`)."),
			"role_id": parentAttribute("Role or git access profile ID (`rol_…`).", "rol"),
			"triggers": schema.MapAttribute{
				MarkdownDescription: "Arbitrary values; changing any of them generates a new key (rotation).",
				ElementType:         types.StringType, Optional: true,
				PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()},
			},
			"public_key": computedString("OpenSSH public key with a `hallpass:<server>/<role>` comment, for git hosts and other " +
				"places that take a bare key."),
			"authorized_keys_line": computedString("Line for the remote user's `~/.ssh/authorized_keys`, with `restrict` and " +
				"`from=\"<gateway egress>\"` options, plus `pty` when the role has that capability (so it changes when the role's " +
				"capabilities do, and is refreshed on the next plan)."),
			"fingerprint": computedString("SHA-256 fingerprint."),
			"algorithm":   computedString("Key algorithm."),
		},
	}
}

func (m *loginKeyModel) fill(c *client.LoginCredential) {
	m.ID = types.StringValue(c.ID)
	m.RoleID = types.StringValue(c.RoleID)
	m.Fingerprint = types.StringValue(c.Fingerprint)
	m.Algorithm = types.StringValue(c.Algorithm)
	m.AuthorizedKeysLine = types.StringValue(c.AuthorizedKeysLine)
	m.PublicKey = types.StringValue(bareKey(c))
}

// bareKey is the public key with HallPass's comment, as git hosts take it (no authorized_keys options).
func bareKey(c *client.LoginCredential) string {
	line := c.AuthorizedKeysLine
	for i := len(line) - 1; i >= 0; i-- {
		if line[i] == ' ' {
			if comment := line[i+1:]; len(comment) > 9 && comment[:9] == "hallpass:" {
				return c.PublicKey + " " + comment
			}
			break
		}
	}
	return c.PublicKey
}

func (r *loginKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan loginKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.GenerateCredential(ctx, plan.RoleID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot generate login key", err)
		return
	}
	plan.fill(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *loginKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state loginKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.GetCredential(ctx, state.RoleID.ValueString(), state.ID.ValueString())
	if client.IsNotFound(err) || (err == nil && (c.State == "revoked" || c.State == "retired")) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read login key", err)
		return
	}
	state.fill(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *loginKeyResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *loginKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state loginKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeCredential(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot revoke login key", err)
	}
}

func (r *loginKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitID(req.ID, 2, "<role_id>/<key_id>")
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("triggers"), types.MapNull(types.StringType))...)
}

// ---- hallpass_login_key_activation

type loginKeyActivationResource struct{ baseResource }

// NewLoginKeyActivationResource returns the hallpass_login_key_activation resource.
func NewLoginKeyActivationResource() resource.Resource { return &loginKeyActivationResource{} }

type loginKeyActivationModel struct {
	ID         types.String `tfsdk:"id"`
	RoleID     types.String `tfsdk:"role_id"`
	LoginKeyID types.String `tfsdk:"login_key_id"`
	Force      types.Bool   `tfsdk:"force"`
	State      types.String `tfsdk:"state"`
}

func (r *loginKeyActivationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_login_key_activation"
}

func (r *loginKeyActivationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Activates a login key once it is installed: HallPass first test-logs-in to the server or git host " +
			"(probe) and activates the key only if that works. Make it depend on whatever installs the key (for example a " +
			"`github_repository_deploy_key`). The previously active key of the role keeps working for its overlap window, then " +
			"retires. Destroying this resource does not deactivate the key; destroy the `hallpass_login_key` to revoke it.",
		Attributes: map[string]schema.Attribute{
			"id":           idAttribute("The login key ID."),
			"role_id":      parentAttribute("Role or git access profile ID (`rol_…`).", "rol"),
			"login_key_id": parentAttribute("Login key ID (`cred_…`).", "cred"),
			"force": schema.BoolAttribute{
				MarkdownDescription: "Activate without a successful test login. Only for hosts the gateway cannot reach yet.",
				Optional:            true, Computed: true, Default: booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"state": computedString("Login key state (`active`, or `retiring` after a newer key was activated)."),
		},
	}
}

func (r *loginKeyActivationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan loginKeyActivationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.LoginKeyID.ValueString()
	force := plan.Force.ValueBool()
	if !force {
		if _, err := r.client.ProbeCredential(ctx, id); err != nil {
			apiError(&resp.Diagnostics, "Test login with the login key failed; is it installed on the host?", err)
			return
		}
	}
	c, err := r.client.ActivateCredential(ctx, id, force)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot activate login key", err)
		return
	}
	plan.ID, plan.State = types.StringValue(c.ID), types.StringValue(c.State)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *loginKeyActivationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state loginKeyActivationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.GetCredential(ctx, state.RoleID.ValueString(), state.LoginKeyID.ValueString())
	if client.IsNotFound(err) || (err == nil && c.State != "active" && c.State != "retiring") {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read login key", err)
		return
	}
	state.State = types.StringValue(c.State)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *loginKeyActivationResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *loginKeyActivationResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	// Activation cannot be undone; revoking happens when the hallpass_login_key is destroyed.
}
