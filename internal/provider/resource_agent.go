package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var _ resource.ResourceWithImportState = (*agentResource)(nil)

type agentResource struct{ baseResource }

// NewAgentResource returns the hallpass_agent resource.
func NewAgentResource() resource.Resource { return &agentResource{} }

type agentModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	SourceCIDRs types.Set    `tfsdk:"source_cidrs"`
	Groups      types.Set    `tfsdk:"groups"`
	Labels      types.Map    `tfsdk:"labels"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (r *agentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent"
}

func groupsAttribute(what string) schema.SetAttribute {
	return schema.SetAttribute{
		MarkdownDescription: "Groups of the " + what + ", used by policy selectors.",
		ElementType:         types.StringType, Optional: true, Computed: true, Default: setdefault.StaticValue(setOf(nil)),
		Validators: []validator.Set{setvalidator.ValueStringsAre(nameValidators()...)},
	}
}

func labelsAttribute(what string) schema.MapAttribute {
	return schema.MapAttribute{
		MarkdownDescription: "Labels of the " + what + ", used by policy selectors.",
		ElementType:         types.StringType, Optional: true, Computed: true, Default: mapdefault.StaticValue(mapOf(nil)),
	}
}

func enabledAttribute(what string) schema.BoolAttribute {
	return schema.BoolAttribute{
		MarkdownDescription: "Whether the " + what + " is enabled. Disabling ends active access within seconds and cancels pending " +
			"requests; enabling lets policy decide again.",
		Optional: true, Computed: true, Default: booldefault.StaticBool(true),
	}
}

func descriptionAttribute(limit int) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: "Description, shown to operators.", Optional: true, Computed: true,
		Default: stringdefault.StaticString(""), Validators: []validator.String{stringvalidator.LengthAtMost(limit)}}
}

func (r *agentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An AI agent identity. The agent signs in to the gateway with its keys (see `hallpass_agent_key`); policy " +
			"rules decide what it may reach. Destroying it deletes the agent: its access ends and its keys are revoked for good (a " +
			"revoked key can never be registered again). Import with the agent ID.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("Agent ID (`agt_…`)."),
			"name":        schema.StringAttribute{MarkdownDescription: "Unique name.", Required: true, Validators: nameValidators()},
			"description": descriptionAttribute(1000),
			"source_cidrs": schema.SetAttribute{
				MarkdownDescription: "Networks the agent may connect from, in canonical form (`10.1.0.0/16`). Empty means any source.",
				ElementType:         types.StringType, Optional: true, Computed: true, Default: setdefault.StaticValue(setOf(nil)),
				Validators: []validator.Set{setvalidator.ValueStringsAre(canonicalCIDR{})},
			},
			"groups":  groupsAttribute("agent"),
			"labels":  labelsAttribute("agent"),
			"enabled": enabledAttribute("agent"),
		},
	}
}

func (m *agentModel) fill(a *client.Agent) {
	m.ID = types.StringValue(a.ID)
	m.Name = types.StringValue(a.Name)
	m.Description = types.StringValue(a.Description)
	m.SourceCIDRs = setOf(a.SourceCIDRs)
	m.Groups = setOf(a.Groups)
	m.Labels = mapOf(a.Labels)
	m.Enabled = types.BoolValue(a.Enabled)
}

func (r *agentResource) toInput(ctx context.Context, m agentModel, d *diag.Diagnostics) client.AgentInput {
	return client.AgentInput{Name: m.Name.ValueString(), Description: m.Description.ValueString(),
		SourceCIDRs: stringsOf(ctx, m.SourceCIDRs, d), Groups: stringsOf(ctx, m.Groups, d), Labels: stringMapOf(ctx, m.Labels, d)}
}

func (r *agentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := r.toInput(ctx, plan, &resp.Diagnostics)
	in.Enabled = ptr(plan.Enabled.ValueBool())
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.CreateAgent(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create agent", err)
		return
	}
	plan.fill(a)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, a.Version)...)
}

func (r *agentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	a, err := r.client.GetAgent(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read agent", err)
		return
	}
	state.fill(a)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, a.Version)...)
}

func (r *agentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state agentModel
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
	a, err := r.client.UpdateAgent(ctx, id, loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update agent", err)
		return
	}
	if a.Enabled != plan.Enabled.ValueBool() {
		if a, err = r.client.SetAgentEnabled(ctx, id, plan.Enabled.ValueBool()); err != nil {
			apiError(&resp.Diagnostics, "Cannot change whether the agent is enabled", err)
			return
		}
	}
	plan.fill(a)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, a.Version)...)
}

func (r *agentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteAgent(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete agent", err)
	}
}

func (r *agentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
