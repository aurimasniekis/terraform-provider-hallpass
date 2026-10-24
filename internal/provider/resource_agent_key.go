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

var _ resource.ResourceWithImportState = (*agentKeyResource)(nil)

type agentKeyResource struct{ baseResource }

// NewAgentKeyResource returns the hallpass_agent_key resource.
func NewAgentKeyResource() resource.Resource { return &agentKeyResource{} }

type agentKeyModel struct {
	ID          types.String `tfsdk:"id"`
	AgentID     types.String `tfsdk:"agent_id"`
	PublicKey   types.String `tfsdk:"public_key"`
	Fingerprint types.String `tfsdk:"fingerprint"`
	Algorithm   types.String `tfsdk:"algorithm"`
}

func (r *agentKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_key"
}

func (r *agentKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A public key an agent signs in with. Destroying it revokes the key: connections using it end within " +
			"seconds, and the key can never be registered again (on any agent), so rotate by adding a new key first. Import with " +
			"`<agent_id>/<key_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":       idAttribute("Key ID (`key_…`)."),
			"agent_id": parentAttribute("Agent ID (`agt_…`).", "agt"),
			"public_key": schema.StringAttribute{
				MarkdownDescription: "OpenSSH public key (`ssh-ed25519 AAAA… comment`). Changing it forces a new key.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"fingerprint": computedString("SHA-256 fingerprint."),
			"algorithm":   computedString("Key algorithm."),
		},
	}
}

func (r *agentKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := r.client.AddAgentKey(ctx, plan.AgentID.ValueString(), plan.PublicKey.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot add agent key", err)
		return
	}
	plan.ID, plan.Fingerprint, plan.Algorithm = types.StringValue(k.ID), types.StringValue(k.Fingerprint), types.StringValue(k.Algorithm)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := r.client.GetAgentKey(ctx, state.AgentID.ValueString(), state.ID.ValueString())
	if client.IsNotFound(err) || (err == nil && k.State != "active") {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read agent key", err)
		return
	}
	state.Fingerprint, state.Algorithm = types.StringValue(k.Fingerprint), types.StringValue(k.Algorithm)
	if state.PublicKey.IsNull() { // import: HallPass keeps the comment separately
		line := k.PublicKey
		if k.Comment != "" {
			line += " " + k.Comment
		}
		state.PublicKey = types.StringValue(line)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *agentKeyResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *agentKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeAgentKey(ctx, state.AgentID.ValueString(), state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot revoke agent key", err)
	}
}

func (r *agentKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := splitID(req.ID, 2, "<agent_id>/<key_id>")
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("agent_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[1])...)
}
