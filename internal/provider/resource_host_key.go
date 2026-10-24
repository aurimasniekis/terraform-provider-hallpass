package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var _ resource.ResourceWithImportState = (*hostKeyResource)(nil)

type hostKeyResource struct{ baseResource }

// NewHostKeyResource returns the hallpass_host_key resource.
func NewHostKeyResource() resource.Resource { return &hostKeyResource{} }

type hostKeyModel struct {
	ID          types.String `tfsdk:"id"`
	ServerID    types.String `tfsdk:"server_id"`
	PublicKey   types.String `tfsdk:"public_key"`
	Fingerprint types.String `tfsdk:"fingerprint"`
	Algorithm   types.String `tfsdk:"algorithm"`
}

func (r *hostKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host_key"
}

func (r *hostKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A pinned host key of a server or git remote. The gateway refuses to connect unless the host presents a " +
			"pinned key. The key is trusted as soon as it is created, so take it from a trusted source (your provisioning, or the " +
			"provider's published keys), never from an unverified scan. Destroying it retires the key. Import with " +
			"`<server_id>/<host_key_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":        idAttribute("Host key ID (`hid_…`)."),
			"server_id": parentAttribute("Server or git remote ID (`srv_…`).", "srv"),
			"public_key": schema.StringAttribute{
				MarkdownDescription: "Host public key, as a `known_hosts` or `authorized_keys` style line (`ssh-ed25519 AAAA…`). " +
					"Changing it forces a new key.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"fingerprint": computedString("SHA-256 fingerprint."),
			"algorithm":   computedString("Key algorithm."),
		},
	}
}

func (r *hostKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hostKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := r.client.AddHostIdentity(ctx, plan.ServerID.ValueString(), plan.PublicKey.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot pin host key", err)
		return
	}
	plan.ID, plan.Fingerprint, plan.Algorithm = types.StringValue(h.ID), types.StringValue(h.Fingerprint), types.StringValue(h.Algorithm)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *hostKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hostKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := r.client.GetHostIdentity(ctx, state.ServerID.ValueString(), state.ID.ValueString())
	if client.IsNotFound(err) || (err == nil && h.State != "active") {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read host key", err)
		return
	}
	state.Fingerprint, state.Algorithm = types.StringValue(h.Fingerprint), types.StringValue(h.Algorithm)
	if state.PublicKey.IsNull() {
		state.PublicKey = types.StringValue(h.PublicKey) // import
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *hostKeyResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *hostKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hostKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RetireHostIdentity(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot retire host key", err)
	}
}

func (r *hostKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitID(req.ID, 2, "<server_id>/<host_key_id>")
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("server_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[1])...)
}
