// Package provider implements the HallPass Terraform provider with terraform-plugin-framework.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// Environment variables read by the provider.
const (
	EnvEndpoint = "HALLPASS_ENDPOINT"
	EnvToken    = "HALLPASS_TOKEN"
	EnvCAFile   = "HALLPASS_CA_FILE"
)

var _ provider.Provider = (*hallpassProvider)(nil)

type hallpassProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
	CAFile   types.String `tfsdk:"ca_file"`
}

// New returns a provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &hallpassProvider{version: version} }
}

func (p *hallpassProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "hallpass"
	resp.Version = p.version
}

func (p *hallpassProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a [HallPass](https://github.com/aurimasniekis/go-hallpass) gateway (a terminating SSH gateway for " +
			"AI agents) through its API: agents and keys, servers and git remotes, roles and access profiles, host keys, login keys, " +
			"policy, single sign-on and chat approvals. Authenticate with an API token (`hallpass_at_…`) created under " +
			"**Administration → API tokens**.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Public URL of HallPass, for example `https://hallpass.example.com`. May also be set with the `" +
					EnvEndpoint + "` environment variable.",
				Optional: true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "API token (`hallpass_at_…`). May also be set with the `" + EnvToken + "` environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
			"ca_file": schema.StringAttribute{
				MarkdownDescription: "Path to a PEM file with additional CA certificates to trust (private PKI). May also be set with `" +
					EnvCAFile + "`.",
				Optional: true,
			},
		},
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func (p *hallpassProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, v := range map[string]types.String{"endpoint": cfg.Endpoint, "token": cfg.Token, "ca_file": cfg.CAFile} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider configuration",
				"The provider cannot be configured with a value that is only known after apply. Set "+name+" statically or via the environment.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	endpoint := firstNonEmpty(cfg.Endpoint.ValueString(), os.Getenv(EnvEndpoint))
	token := firstNonEmpty(cfg.Token.ValueString(), os.Getenv(EnvToken))
	caFile := firstNonEmpty(cfg.CAFile.ValueString(), os.Getenv(EnvCAFile))
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing HallPass endpoint",
			"Set the endpoint argument or the "+EnvEndpoint+" environment variable to the public URL of HallPass.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Missing HallPass API token",
			"Set the token argument or the "+EnvToken+" environment variable to an API token (hallpass_at_…).")
	} else if err := client.ValidateToken(token); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Invalid HallPass API token", err.Error())
	}
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := client.New(client.Config{
		Endpoint:  endpoint,
		Token:     token,
		CAFile:    caFile,
		UserAgent: "terraform-provider-hallpass/" + p.version,
		Observer: func(ctx context.Context, method, apiPath string, status, attempt int, err error) {
			fields := map[string]any{"method": method, "path": apiPath, "status": status, "attempt": attempt}
			if err != nil {
				fields["error"] = err.Error()
			}
			tflog.Debug(ctx, "hallpass API request", fields)
		},
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot configure the HallPass client", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *hallpassProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAgentResource,
		NewAgentKeyResource,
		NewServerResource,
		NewGitRemoteResource,
		NewHostKeyResource,
		NewRoleResource,
		NewGitAccessProfileResource,
		NewLoginKeyResource,
		NewLoginKeyActivationResource,
		NewPolicyRuleResource,
		NewApproverRuleResource,
		NewSelfApprovalResource,
		NewOIDCProviderResource,
		NewOIDCGroupMappingResource,
		NewAuthSettingsResource,
		NewBackupTargetResource,
		NewIntegrationResource,
		NewNotificationRouteResource,
	}
}

func (p *hallpassProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewServerDataSource,
		NewAgentDataSource,
		NewRoleDataSource,
		NewOperatorDataSource,
		NewGatewayHostKeysDataSource,
	}
}
