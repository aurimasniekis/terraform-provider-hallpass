package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// ---- hallpass_api_target

var _ resource.ResourceWithImportState = (*apiTargetResource)(nil)

type apiTargetResource struct{ baseResource }

// NewAPITargetResource returns the hallpass_api_target resource.
func NewAPITargetResource() resource.Resource { return &apiTargetResource{} }

type apiTargetModel struct {
	ID            types.String `tfsdk:"id"`
	Alias         types.String `tfsdk:"alias"`
	DisplayName   types.String `tfsdk:"display_name"`
	Description   types.String `tfsdk:"description"`
	Hosts         types.List   `tfsdk:"hosts"`
	Groups        types.Set    `tfsdk:"groups"`
	Labels        types.Map    `tfsdk:"labels"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	CACertificate types.String `tfsdk:"ca_certificate"`
	CAFingerprint types.String `tfsdk:"ca_fingerprint"`
}

func (r *apiTargetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_target"
}

func (r *apiTargetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An HTTPS API (GitHub, Cloudflare, Google Cloud, …) agents call with their usual tools through the gateway's " +
			"API proxy, which adds the credential of a `hallpass_api_access_profile` so agents never hold it. Agents trust the target's " +
			"CA (`ca_certificate`), which can only sign certificates for its hosts. Destroying it deletes the target and its profiles: " +
			"access ends and their credentials are destroyed. Import with the server ID.",
		Attributes: map[string]schema.Attribute{
			"id":    idAttribute("Server ID (`srv_…`)."),
			"alias": schema.StringAttribute{MarkdownDescription: "Unique name agents request access with. Gateway command words are reserved.", Required: true, Validators: aliasValidators()},
			"display_name": schema.StringAttribute{MarkdownDescription: "Display name (defaults to the alias).", Optional: true, Computed: true,
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 200)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"description": descriptionAttribute(2000),
			"hosts": schema.ListAttribute{MarkdownDescription: "HTTPS host names, exact (`api.github.com`) or `*.domain` wildcards " +
				"(`*.googleapis.com`, every subdomain). No IP addresses; port 443 only. They must resolve to addresses the gateway's " +
				"`api_proxy` settings allow (public addresses by default). Changing them issues a new CA.",
				ElementType: types.StringType, Required: true, Validators: []validator.List{listvalidator.SizeBetween(1, 20), listvalidator.UniqueValues()}},
			"groups":  groupsAttribute("API target"),
			"labels":  labelsAttribute("API target"),
			"enabled": enabledAttribute("API target"),
			"ca_certificate": schema.StringAttribute{MarkdownDescription: "PEM certificate of the target's proxy CA, for agents to trust " +
				"(they can also fetch it with `ssh <gateway> api ca`).", Computed: true},
			"ca_fingerprint": schema.StringAttribute{MarkdownDescription: "SHA-256 fingerprint of the CA.", Computed: true},
		},
	}
}

func (m *apiTargetModel) fill(s *client.Server, ca *client.APITargetCA) {
	m.ID = types.StringValue(s.ID)
	m.Alias = types.StringValue(s.Alias)
	m.DisplayName = types.StringValue(s.DisplayName)
	m.Description = types.StringValue(s.Description)
	var hosts []string
	if s.API != nil {
		hosts = s.API.Hosts
	}
	m.Hosts = listOf(hosts)
	m.Groups = setOf(s.Groups)
	m.Labels = mapOf(s.Labels)
	m.Enabled = types.BoolValue(s.Enabled)
	m.CACertificate, m.CAFingerprint = types.StringValue(""), types.StringValue("")
	if ca != nil {
		m.CACertificate, m.CAFingerprint = types.StringValue(ca.Certificate), types.StringValue(ca.Fingerprint)
	}
}

func (m apiTargetModel) input(ctx context.Context, d *diag.Diagnostics) client.ServerInput {
	var hosts []string
	d.Append(m.Hosts.ElementsAs(ctx, &hosts, false)...)
	in := client.ServerInput{Alias: m.Alias.ValueString(), Description: m.Description.ValueString(), API: &client.APITarget{Hosts: hosts},
		Groups: stringsOf(ctx, m.Groups, d), Labels: stringMapOf(ctx, m.Labels, d), Metadata: map[string]string{}}
	if !m.DisplayName.IsUnknown() && !m.DisplayName.IsNull() {
		in.DisplayName = m.DisplayName.ValueString()
	}
	return in
}

// load reads the target and its CA.
func (r *apiTargetResource) load(ctx context.Context, s *client.Server, m *apiTargetModel, d *diag.Diagnostics) {
	ca, err := r.client.GetAPITargetCA(ctx, s.ID)
	if err != nil {
		apiError(d, "Cannot read the API target's CA", err)
		return
	}
	m.fill(s, ca)
}

func (r *apiTargetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiTargetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.input(ctx, &resp.Diagnostics)
	in.Kind, in.Enabled = "api", ptr(plan.Enabled.ValueBool())
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.CreateServer(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create API target", err)
		return
	}
	r.load(ctx, s, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, s.Version)...)
}

func (r *apiTargetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiTargetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.GetServer(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read API target", err)
		return
	}
	if s.Kind != "api" {
		resp.Diagnostics.AddError("Wrong resource type", "HallPass server "+s.ID+" is of kind "+s.Kind+
			"; manage servers with hallpass_server and git remotes with hallpass_git_remote.")
		return
	}
	r.load(ctx, s, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, s.Version)...)
}

func (r *apiTargetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state apiTargetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.input(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	s, err := r.client.UpdateServer(ctx, id, loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update API target", err)
		return
	}
	if s.Enabled != plan.Enabled.ValueBool() {
		if s, err = r.client.SetServerEnabled(ctx, id, plan.Enabled.ValueBool()); err != nil {
			apiError(&resp.Diagnostics, "Cannot change whether the API target is enabled", err)
			return
		}
	}
	r.load(ctx, s, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, s.Version)...)
}

func (r *apiTargetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiTargetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteServer(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete API target", err)
	}
}

func (r *apiTargetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- hallpass_api_access_profile

var _ resource.ResourceWithImportState = (*apiProfileResource)(nil)

type apiProfileResource struct{ baseResource }

// NewAPIAccessProfileResource returns the hallpass_api_access_profile resource.
func NewAPIAccessProfileResource() resource.Resource { return &apiProfileResource{} }

type apiProfileModel struct {
	ID                types.String `tfsdk:"id"`
	ServerID          types.String `tfsdk:"server_id"`
	Alias             types.String `tfsdk:"alias"`
	Description       types.String `tfsdk:"description"`
	Rules             types.List   `tfsdk:"rules"`
	ApprovalsRequired types.Int64  `tfsdk:"approvals_required"`
	DefaultDuration   types.String `tfsdk:"default_duration"`
	MaxDuration       types.String `tfsdk:"max_duration"`
	Labels            types.Map    `tfsdk:"labels"`
	Enabled           types.Bool   `tfsdk:"enabled"`
}

type apiRuleModel struct {
	Effect  types.String `tfsdk:"effect"`
	Methods types.Set    `tfsdk:"methods"`
	Hosts   types.Set    `tfsdk:"hosts"`
	Paths   types.Set    `tfsdk:"paths"`
	GraphQL types.Set    `tfsdk:"graphql"`
}

var apiRuleType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"effect": types.StringType, "methods": types.SetType{ElemType: types.StringType}, "hosts": types.SetType{ElemType: types.StringType},
	"paths": types.SetType{ElemType: types.StringType}, "graphql": types.SetType{ElemType: types.StringType},
}}

func (r *apiProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_access_profile"
}

func (r *apiProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	optSet := func(desc string, v ...validator.Set) schema.SetAttribute {
		return schema.SetAttribute{MarkdownDescription: desc, ElementType: types.StringType, Optional: true, Validators: v}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "An access profile of an API target: which requests agents may make through the API proxy. Agents request " +
			"it like a role; `hallpass_policy_rule` decides who may and whether it is approved automatically. Set its credential with " +
			"`hallpass_api_credential`. A request is allowed when an allow rule matches and no deny rule does; matching is " +
			"case-insensitive. Destroying it deletes the profile: access ends and its credential is destroyed. Import with the role ID.",
		Attributes: map[string]schema.Attribute{
			"id":          idAttribute("Profile ID (`rol_…`)."),
			"server_id":   parentAttribute("API target ID (`srv_…`).", "srv"),
			"alias":       schema.StringAttribute{MarkdownDescription: "Profile name, unique on the target.", Required: true, Validators: aliasValidators()},
			"description": descriptionAttribute(2000),
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "Allow and deny rules (at least one allow rule). Empty lists match anything.",
				Required:            true,
				Validators:          []validator.List{listvalidator.SizeBetween(1, 100)},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"effect": schema.StringAttribute{MarkdownDescription: "`allow` or `deny`.", Required: true,
						Validators: []validator.String{stringvalidator.OneOf("allow", "deny")}},
					"methods": optSet("HTTP methods (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`).",
						setvalidator.ValueStringsAre(stringvalidator.OneOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"))),
					"hosts": optSet("Hosts of the target the rule applies to (exact or `*.domain`)."),
					"paths": optSet("Path patterns starting with `/`: `*` matches within one segment, `**` any number of segments, " +
						"`{a,b}` either alternative. An escaped slash stays inside its segment."),
					"graphql": optSet("Match GraphQL requests by operation type (`query`, `mutation`, `subscription`). An allow rule "+
						"matches only when every operation is of a listed type; a deny rule when any is, or when they cannot be determined.",
						setvalidator.ValueStringsAre(stringvalidator.OneOf("query", "mutation", "subscription"))),
				}},
			},
			"approvals_required": approvalsRequiredAttribute(),
			"default_duration":   durationAttribute("Access duration when the agent does not ask for one.", "30m"),
			"max_duration":       durationAttribute("Longest access an agent may request (policy may lower it).", "6h"),
			"labels":             labelsAttribute("profile"),
			"enabled":            enabledAttribute("profile"),
		},
	}
}

func (m *apiProfileModel) fill(ro *client.Role) {
	m.ID = types.StringValue(ro.ID)
	m.ServerID = types.StringValue(ro.ServerID)
	m.Alias = types.StringValue(ro.Alias)
	m.Description = types.StringValue(ro.Description)
	var rules []attr.Value
	if ro.API != nil {
		for _, r := range ro.API.Rules {
			rules = append(rules, types.ObjectValueMust(apiRuleType.AttrTypes, map[string]attr.Value{
				"effect": types.StringValue(r.Effect), "methods": optSetOf(r.Methods), "hosts": optSetOf(r.Hosts),
				"paths": optSetOf(r.Paths), "graphql": optSetOf(r.GraphQL),
			}))
		}
	}
	m.Rules = types.ListValueMust(apiRuleType, rules)
	m.ApprovalsRequired = types.Int64Value(ro.ApprovalsRequired)
	m.DefaultDuration = durationOf(m.DefaultDuration, ro.DefaultDuration)
	m.MaxDuration = durationOf(m.MaxDuration, ro.MaxDuration)
	m.Labels = mapOf(ro.Labels)
	m.Enabled = types.BoolValue(ro.Enabled)
}

func (m apiProfileModel) input(ctx context.Context, d *diag.Diagnostics) client.RoleInput {
	var rules []apiRuleModel
	d.Append(m.Rules.ElementsAs(ctx, &rules, false)...)
	api := &client.APIRules{Rules: []client.APIRule{}}
	for _, r := range rules {
		api.Rules = append(api.Rules, client.APIRule{Effect: r.Effect.ValueString(), Methods: stringsOf(ctx, r.Methods, d),
			Hosts: stringsOf(ctx, r.Hosts, d), Paths: stringsOf(ctx, r.Paths, d), GraphQL: stringsOf(ctx, r.GraphQL, d)})
	}
	return client.RoleInput{Alias: m.Alias.ValueString(), Description: m.Description.ValueString(), Capabilities: []string{"api"}, API: api,
		DefaultDuration: seconds(m.DefaultDuration), MaxDuration: seconds(m.MaxDuration), ApprovalsRequired: m.ApprovalsRequired.ValueInt64(),
		Labels: stringMapOf(ctx, m.Labels, d)}
}

func (r *apiProfileResource) crud() roleCRUD[apiProfileModel] {
	return roleCRUD[apiProfileModel]{client: r.client, noun: "API access profile", kind: "api",
		input: func(ctx context.Context, m apiProfileModel, d *diag.Diagnostics) client.RoleInput {
			return m.input(ctx, d)
		},
		fill: func(m *apiProfileModel, ro *client.Role) { m.fill(ro) },
		ids:  func(m *apiProfileModel) (types.String, types.String) { return m.ID, m.ServerID },
		on:   func(m *apiProfileModel) bool { return m.Enabled.ValueBool() }}
}

func (r *apiProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.crud().create(ctx, req, resp)
}

func (r *apiProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.crud().read(ctx, req, resp)
}

func (r *apiProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.crud().update(ctx, req, resp)
}

func (r *apiProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.crud().delete(ctx, req, resp)
}

func (r *apiProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- hallpass_api_credential

var _ resource.ResourceWithValidateConfig = (*apiCredentialResource)(nil)

type apiCredentialResource struct{ baseResource }

// NewAPICredentialResource returns the hallpass_api_credential resource.
func NewAPICredentialResource() resource.Resource { return &apiCredentialResource{} }

type apiCredentialModel struct {
	ID       types.String `tfsdk:"id"`
	RoleID   types.String `tfsdk:"role_id"`
	Type     types.String `tfsdk:"type"`
	Header   types.String `tfsdk:"header"`
	Username types.String `tfsdk:"username"`
	Scopes   types.List   `tfsdk:"scopes"`
	Secret   types.String `tfsdk:"secret"`
	// SecretWO is write-only: only the configuration holds it, never the plan or state.
	SecretWO        types.String `tfsdk:"secret_wo"`
	SecretWOVersion types.Int64  `tfsdk:"secret_wo_version"`
	Hint            types.String `tfsdk:"hint"`
	Version         types.Int64  `tfsdk:"version"`
}

func (r *apiCredentialResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_credential"
}

func (r *apiCredentialResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The credential HallPass adds to an API access profile's requests. The secret is encrypted in HallPass, " +
			"never returned and never shown to agents. Give it as `secret` (kept in state, sensitive) or, with Terraform 1.11 or " +
			"later, as write-only `secret_wo` (never stored in plan or state; for example from an ephemeral resource), sent when the " +
			"credential is created and whenever `secret_wo_version` changes. Changing it applies to the next proxied request. Destroying it removes the credential: the profile's requests fail until a new one is set.",
		Attributes: map[string]schema.Attribute{
			"id":      idAttribute("The access profile ID (the credential has no ID of its own)."),
			"role_id": parentAttribute("API access profile ID (`rol_…`).", "rol"),
			"type": schema.StringAttribute{MarkdownDescription: "`bearer` (`Authorization: Bearer <secret>`), `header` (`<header>: <secret>`), " +
				"`basic` (HTTP Basic with `username`) or `google_service_account` (a service account key in JSON; HallPass sends short-lived " +
				"access tokens).", Required: true,
				Validators: []validator.String{stringvalidator.OneOf("bearer", "header", "basic", "google_service_account")}},
			"header":   schema.StringAttribute{MarkdownDescription: "Header name for type `header`, e.g. `X-Api-Key`.", Optional: true},
			"username": schema.StringAttribute{MarkdownDescription: "Username for type `basic`.", Optional: true},
			"scopes": schema.ListAttribute{MarkdownDescription: "OAuth scopes for type `google_service_account` (default " +
				"`https://www.googleapis.com/auth/cloud-platform`).", ElementType: types.StringType, Optional: true},
			"secret": schema.StringAttribute{MarkdownDescription: "The token, password or service account key, kept in state. Exactly one " +
				"of `secret` and `secret_wo` is required.", Optional: true, Sensitive: true},
			"secret_wo": schema.StringAttribute{MarkdownDescription: "The token, password or service account key, write-only: never " +
				"stored in plan or state. Needs `secret_wo_version`.", Optional: true, Sensitive: true, WriteOnly: true},
			"secret_wo_version": schema.Int64Attribute{MarkdownDescription: "Change it to send `secret_wo` again (Terraform cannot see " +
				"changes of a write-only value).", Optional: true},
			// No UseStateForUnknown: both change with every update of the credential.
			"hint":    schema.StringAttribute{MarkdownDescription: "The secret's last four characters, or the service account's email.", Computed: true},
			"version": schema.Int64Attribute{MarkdownDescription: "Increases with every change.", Computed: true},
		},
	}
}

func (r *apiCredentialResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m apiCredentialModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Type.IsUnknown() {
		return
	}
	t := m.Type.ValueString()
	for name, ok := range map[string]bool{
		"header":   m.Header.IsNull() || t == "header",
		"username": m.Username.IsNull() || t == "basic",
		"scopes":   m.Scopes.IsNull() || t == "google_service_account",
	} {
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Not used by this type", name+" does not apply to type "+t+".")
		}
	}
	if t == "header" && m.Header.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("header"), "Missing header", "Type header needs the header name.")
	}
	if t == "basic" && m.Username.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("username"), "Missing username", "Type basic needs a username.")
	}
	if m.Secret.IsUnknown() || m.SecretWO.IsUnknown() {
		return
	}
	switch {
	case m.Secret.IsNull() == m.SecretWO.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("secret"), "Secret", "Set exactly one of secret and secret_wo.")
	case !m.SecretWO.IsNull() && m.SecretWOVersion.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("secret_wo_version"), "Missing secret_wo_version",
			"secret_wo needs secret_wo_version; change it to send a new secret_wo.")
	case !m.Secret.IsNull() && !m.SecretWOVersion.IsNull():
		resp.Diagnostics.AddAttributeError(path.Root("secret_wo_version"), "Not used with secret", "secret_wo_version only applies to secret_wo.")
	}
}

// input builds the request; secretWO is the write-only secret from the configuration ("" when secret is used).
func (m apiCredentialModel) input(ctx context.Context, secretWO string, d *diag.Diagnostics) client.APICredentialInput {
	secret := m.Secret.ValueString()
	if m.Secret.IsNull() {
		secret = secretWO
	}
	in := client.APICredentialInput{Type: m.Type.ValueString(), Header: m.Header.ValueString(), Username: m.Username.ValueString(),
		Secret: secret}
	if !m.Scopes.IsNull() {
		d.Append(m.Scopes.ElementsAs(ctx, &in.Scopes, false)...)
	}
	return in
}

func (m *apiCredentialModel) fill(c *client.APICredential) {
	m.ID = types.StringValue(c.RoleID)
	m.RoleID = types.StringValue(c.RoleID)
	m.Type = types.StringValue(c.Type)
	m.Header, m.Username = optString(c.Header), optString(c.Username)
	if c.Type == "google_service_account" && !m.Scopes.IsNull() {
		m.Scopes = listOf(c.Scopes)
	}
	m.Hint = types.StringValue(c.Hint)
	m.Version = types.Int64Value(c.Version)
}

// set stores the credential; config supplies the write-only secret, which the plan never holds.
func (r *apiCredentialResource) set(ctx context.Context, m *apiCredentialModel, config tfsdk.Config, d *diag.Diagnostics) {
	var secretWO types.String
	d.Append(config.GetAttribute(ctx, path.Root("secret_wo"), &secretWO)...)
	in := m.input(ctx, secretWO.ValueString(), d)
	if d.HasError() {
		return
	}
	c, err := r.client.SetAPICredential(ctx, m.RoleID.ValueString(), in)
	if err != nil {
		apiError(d, "Cannot set API credential", err)
		return
	}
	m.fill(c)
	m.SecretWO = types.StringNull()
}

func (r *apiCredentialResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiCredentialModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.set(ctx, &plan, req.Config, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *apiCredentialResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiCredentialModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.GetAPICredential(ctx, state.RoleID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read API credential", err)
		return
	}
	if c.Version != state.Version.ValueInt64() {
		// Changed outside Terraform: plan sending the configured secret again.
		if state.SecretWOVersion.IsNull() {
			state.Secret = types.StringValue("")
		} else {
			state.SecretWOVersion = types.Int64Null()
		}
	}
	state.fill(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *apiCredentialResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan apiCredentialModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.set(ctx, &plan, req.Config, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *apiCredentialResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiCredentialModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteAPICredential(ctx, state.RoleID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete API credential", err)
	}
}
