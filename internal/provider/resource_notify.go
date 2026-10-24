package provider

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// ---- hallpass_integration

var (
	_ resource.ResourceWithImportState      = (*integrationResource)(nil)
	_ resource.ResourceWithConfigValidators = (*integrationResource)(nil)
)

type integrationResource struct{ baseResource }

// NewIntegrationResource returns the hallpass_integration resource.
func NewIntegrationResource() resource.Resource { return &integrationResource{} }

type slackModel struct {
	TeamID  types.String `tfsdk:"team_id"`
	Command types.String `tfsdk:"command"`
}

type telegramModel struct {
	BotUsername    types.String `tfsdk:"bot_username"`
	AllowedChatIDs types.Set    `tfsdk:"allowed_chat_ids"`
}

type integrationModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Slack       *slackModel    `tfsdk:"slack"`
	Telegram    *telegramModel `tfsdk:"telegram"`
	Secrets     types.Map      `tfsdk:"secrets"`
	Enabled     types.Bool     `tfsdk:"enabled"`
	WebhookPath types.String   `tfsdk:"webhook_path"`
}

func (r *integrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration"
}

func (r *integrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Slack or Telegram integration for approving requests from chat. Configure exactly one of `slack` or " +
			"`telegram`; switching between them forces a new integration. Register `webhook_path` (under the public URL) at the " +
			"provider. Send requests to chats with `hallpass_notification_route`. Secrets are write-only in HallPass and kept in " +
			"state. Import with the integration ID (secrets are not imported; set them again).",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute("Integration ID (`int_…`)."),
			"name": schema.StringAttribute{MarkdownDescription: "Name, unique among integrations.", Required: true,
				Validators: []validator.String{stringvalidator.LengthBetween(1, 64)}},
			"slack": schema.SingleNestedAttribute{
				MarkdownDescription: "Slack app settings. Secrets: `bot_token`, `signing_secret`.",
				Optional:            true,
				PlanModifiers:       []planmodifier.Object{objectplanmodifier.RequiresReplaceIf(providerSwitched, "Switching provider forces a new integration.", "")},
				Attributes: map[string]schema.Attribute{
					"team_id": schema.StringAttribute{MarkdownDescription: "Workspace ID (`T…`).", Required: true},
					"command": schema.StringAttribute{MarkdownDescription: "Slash command (default `/hallpass`).", Optional: true},
				},
			},
			"telegram": schema.SingleNestedAttribute{
				MarkdownDescription: "Telegram bot settings. Secrets: `bot_token`, and optionally `webhook_secret` (generated when omitted).",
				Optional:            true,
				PlanModifiers:       []planmodifier.Object{objectplanmodifier.RequiresReplaceIf(providerSwitched, "Switching provider forces a new integration.", "")},
				Attributes: map[string]schema.Attribute{
					"bot_username": schema.StringAttribute{MarkdownDescription: "Bot username (without `@`).", Optional: true},
					"allowed_chat_ids": schema.SetAttribute{MarkdownDescription: "Group chats besides route destinations that may interact.",
						ElementType: types.Int64Type, Optional: true},
				},
			},
			"secrets": schema.MapAttribute{
				MarkdownDescription: "Secret values by name (see `slack` and `telegram`). Changing one sends only that secret.",
				ElementType:         types.StringType, Optional: true, Sensitive: true,
				Validators: []validator.Map{mapvalidator.KeysAre(stringvalidator.OneOf("bot_token", "signing_secret", "webhook_secret"))},
			},
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether messages are sent.", Optional: true, Computed: true,
				Default: booldefault.StaticBool(true)},
			"webhook_path": computedString("Callback path to register at the provider, under the HallPass public URL."),
		},
	}
}

// providerSwitched forces replacement when the block changes from absent to present (or back): the provider is fixed.
func providerSwitched(_ context.Context, req planmodifier.ObjectRequest, resp *objectplanmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
}

func (r *integrationResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{resourcevalidator.ExactlyOneOf(path.MatchRoot("slack"), path.MatchRoot("telegram"))}
}

func (m integrationModel) provider() string {
	if m.Slack != nil {
		return "slack"
	}
	return "telegram"
}

func (m integrationModel) config(ctx context.Context, d *diag.Diagnostics) map[string]any {
	if m.Slack != nil {
		c := map[string]any{"team_id": m.Slack.TeamID.ValueString()}
		if !m.Slack.Command.IsNull() {
			c["command"] = m.Slack.Command.ValueString()
		}
		return c
	}
	c := map[string]any{}
	if m.Telegram != nil {
		if !m.Telegram.BotUsername.IsNull() {
			c["bot_username"] = m.Telegram.BotUsername.ValueString()
		}
		if !m.Telegram.AllowedChatIDs.IsNull() {
			var ids []int64
			d.Append(m.Telegram.AllowedChatIDs.ElementsAs(ctx, &ids, false)...)
			slices.Sort(ids)
			c["allowed_chat_ids"] = ids
		}
	}
	return c
}

func (m *integrationModel) fill(i *client.Integration) {
	m.ID = types.StringValue(i.ID)
	m.Name = types.StringValue(i.Name)
	m.Enabled = types.BoolValue(i.Enabled)
	m.WebhookPath = types.StringValue(i.WebhookPath)
	str := func(k string) types.String {
		if v, ok := i.Config[k].(string); ok && v != "" {
			return types.StringValue(v)
		}
		return types.StringNull()
	}
	switch i.Provider {
	case "slack":
		cmd := str("command")
		if m.Slack != nil && m.Slack.Command.IsNull() {
			cmd = types.StringNull() // the server's default command is not configuration
		}
		m.Slack, m.Telegram = &slackModel{TeamID: str("team_id"), Command: cmd}, nil
	case "telegram":
		tg := &telegramModel{BotUsername: str("bot_username"), AllowedChatIDs: types.SetNull(types.Int64Type)}
		if raw, ok := i.Config["allowed_chat_ids"]; ok {
			b, _ := json.Marshal(raw)
			var ids []int64
			if json.Unmarshal(b, &ids) == nil && len(ids) > 0 {
				tg.AllowedChatIDs, _ = types.SetValueFrom(context.Background(), types.Int64Type, ids)
			}
		}
		m.Slack, m.Telegram = nil, tg
	}
}

// changedSecrets returns the secrets that differ from the prior state (all of them on create).
func changedSecrets(ctx context.Context, plan, prior types.Map, d *diag.Diagnostics) map[string]string {
	next := stringMapOf(ctx, plan, d)
	if prior.IsNull() {
		return next
	}
	old := stringMapOf(ctx, prior, d)
	out := map[string]string{}
	for k, v := range next {
		if old[k] != v {
			out[k] = v
		}
	}
	for k := range old {
		if _, ok := next[k]; !ok {
			out[k] = "" // removed
		}
	}
	return out
}

func (r *integrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan integrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.IntegrationInput{Provider: plan.provider(), Name: plan.Name.ValueString(), Config: plan.config(ctx, &resp.Diagnostics),
		Secrets: stringMapOf(ctx, plan.Secrets, &resp.Diagnostics), Enabled: plan.Enabled.ValueBool()}
	if resp.Diagnostics.HasError() {
		return
	}
	i, err := r.client.CreateIntegration(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create integration", err)
		return
	}
	plan.fill(i)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, i.Version)...)
}

func (r *integrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state integrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	i, err := r.client.GetIntegration(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read integration", err)
		return
	}
	state.fill(i)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, i.Version)...)
}

func (r *integrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state integrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.IntegrationInput{Name: plan.Name.ValueString(), Config: plan.config(ctx, &resp.Diagnostics),
		Secrets: changedSecrets(ctx, plan.Secrets, state.Secrets, &resp.Diagnostics), Enabled: plan.Enabled.ValueBool()}
	if len(in.Secrets) == 0 {
		in.Secrets = nil
	}
	if resp.Diagnostics.HasError() {
		return
	}
	i, err := r.client.UpdateIntegration(ctx, state.ID.ValueString(), loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update integration", err)
		return
	}
	plan.fill(i)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, i.Version)...)
}

func (r *integrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state integrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteIntegration(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete integration", err)
	}
}

func (r *integrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- hallpass_notification_route

var _ resource.ResourceWithImportState = (*routeResource)(nil)

type routeResource struct{ baseResource }

// NewNotificationRouteResource returns the hallpass_notification_route resource.
func NewNotificationRouteResource() resource.Resource { return &routeResource{} }

type routeModel struct {
	ID            types.String  `tfsdk:"id"`
	IntegrationID types.String  `tfsdk:"integration_id"`
	Destination   types.String  `tfsdk:"destination"`
	Targets       *targetsModel `tfsdk:"targets"`
	Enabled       types.Bool    `tfsdk:"enabled"`
}

func (r *routeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_route"
}

func (r *routeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	targets := targetsAttribute("Requests for which servers and git remotes go to this chat. Changing it forces a new route.", true)
	targets.PlanModifiers = []planmodifier.Object{objectplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Sends approval requests for matching servers to a Slack channel or Telegram chat. Routes cannot be " +
			"edited in place: every change replaces the route. Import with the route ID.",
		Attributes: map[string]schema.Attribute{
			"id":             idAttribute("Route ID (`rte_…`)."),
			"integration_id": parentAttribute("Integration ID (`int_…`).", "int"),
			"destination":    replaceString("Slack channel ID (`C…`) or Telegram chat ID.", true, stringvalidator.LengthBetween(1, 64)),
			"targets":        targets,
			"enabled": schema.BoolAttribute{MarkdownDescription: "Whether messages are sent. Changing it forces a new route.", Optional: true,
				Computed: true, Default: booldefault.StaticBool(true), PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *routeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan routeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	targets := plan.Targets.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	rt, err := r.client.CreateNotificationRoute(ctx, plan.IntegrationID.ValueString(), plan.Destination.ValueString(), targets, plan.Enabled.ValueBool())
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create notification route", err)
		return
	}
	plan.ID = types.StringValue(rt.ID)
	plan.Targets = targetsFrom(rt.Targets)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *routeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state routeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rt, err := r.client.GetNotificationRoute(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read notification route", err)
		return
	}
	state.IntegrationID, state.Destination = types.StringValue(rt.IntegrationID), types.StringValue(rt.Destination)
	state.Targets, state.Enabled = targetsFrom(rt.Targets), types.BoolValue(rt.Enabled)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *routeResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *routeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state routeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteNotificationRoute(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete notification route", err)
	}
}

func (r *routeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
