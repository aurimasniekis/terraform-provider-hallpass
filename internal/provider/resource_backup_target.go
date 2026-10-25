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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// ---- hallpass_backup_target

var _ resource.ResourceWithImportState = (*backupTargetResource)(nil)

type backupTargetResource struct{ baseResource }

// NewBackupTargetResource returns the hallpass_backup_target resource.
func NewBackupTargetResource() resource.Resource { return &backupTargetResource{} }

type backupTargetModel struct {
	ID                  types.String `tfsdk:"id"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	Endpoint            types.String `tfsdk:"endpoint"`
	Region              types.String `tfsdk:"region"`
	Bucket              types.String `tfsdk:"bucket"`
	Prefix              types.String `tfsdk:"prefix"`
	PathStyle           types.Bool   `tfsdk:"path_style"`
	AccessKeyID         types.String `tfsdk:"access_key_id"`
	SecretAccessKey     types.String `tfsdk:"secret_access_key"`
	CABundlePEM         types.String `tfsdk:"ca_bundle_pem"`
	AllowPrivateNetwork types.Bool   `tfsdk:"allow_private_network"`
	Interval            types.String `tfsdk:"interval"`
	KeepLast            types.Int64  `tfsdk:"keep_last"`
	KeepDailyDays       types.Int64  `tfsdk:"keep_daily_days"`
}

func (r *backupTargetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_backup_target"
}

func (r *backupTargetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Scheduled, encrypted backups of HallPass to S3-compatible object storage (AWS S3, Cloudflare R2, " +
			"MinIO and others). Installation-wide: declare it at most once. Each backup is a database snapshot, encrypted on the " +
			"server with a key protected by the KEK, plus the recordings it refers to (already encrypted, uploaded once). " +
			"Restoring needs the KEK, so keep it backed up separately. Destroying the resource stops backups and leaves the " +
			"objects in the bucket. The secret access key is write-only in HallPass and kept in state. Import with `backup-target` " +
			"(the secret is not imported; the next apply sends it).",
		Attributes: map[string]schema.Attribute{
			"id": idAttribute("Always `backup-target`."),
			"enabled": schema.BoolAttribute{MarkdownDescription: "Run scheduled backups. When false the target is kept but paused.",
				Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"endpoint": schema.StringAttribute{MarkdownDescription: "Service origin, e.g. `https://s3.eu-central-1.amazonaws.com` or " +
				"`https://<account>.r2.cloudflarestorage.com`. Changing the endpoint, bucket, prefix or `path_style` starts over in the new " +
				"location; objects in the old one are left alone.", Required: true},
			"region": schema.StringAttribute{MarkdownDescription: "Region (default `us-east-1`; `auto` for Cloudflare R2).",
				Optional: true, Computed: true, Default: stringdefault.StaticString("us-east-1"),
				Validators: []validator.String{stringvalidator.LengthBetween(1, 32)}},
			"bucket": schema.StringAttribute{MarkdownDescription: "Bucket name.", Required: true,
				Validators: []validator.String{stringvalidator.LengthBetween(3, 63)}},
			"prefix": schema.StringAttribute{MarkdownDescription: "Key prefix, empty or ending with a slash (e.g. `hallpass/`).",
				Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"path_style": schema.BoolAttribute{MarkdownDescription: "Address the bucket as `endpoint/bucket` (MinIO and some providers).",
				Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"access_key_id": schema.StringAttribute{MarkdownDescription: "Access key ID. The key needs list, read, write and delete below the prefix.",
				Required: true},
			"secret_access_key": schema.StringAttribute{MarkdownDescription: "Secret access key. Sent only when it changes.",
				Required: true, Sensitive: true},
			"ca_bundle_pem": schema.StringAttribute{MarkdownDescription: "Extra trust roots (PEM) for an endpoint with a private CA.",
				Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"allow_private_network": schema.BoolAttribute{MarkdownDescription: "Allow an endpoint that resolves to a private, loopback or link-local address.",
				Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"interval": schema.StringAttribute{MarkdownDescription: "Time between backups, `15m` to `168h` (default `1h`). A failed backup is retried within 15 minutes.",
				Optional: true, Computed: true, Default: stringdefault.StaticString("1h"), Validators: []validator.String{durationValidator()}},
			"keep_last": schema.Int64Attribute{MarkdownDescription: "Newest successful backups to keep (default 48).",
				Optional: true, Computed: true, Default: int64default.StaticInt64(48), Validators: []validator.Int64{int64validator.Between(1, 1000)}},
			"keep_daily_days": schema.Int64Attribute{MarkdownDescription: "Also keep the newest backup of each of this many past days (default 30; 0 keeps only the newest).",
				Optional: true, Computed: true, Default: int64default.StaticInt64(30), Validators: []validator.Int64{int64validator.Between(0, 3650)}},
		},
	}
}

func (m backupTargetModel) input(secret bool) client.BackupTargetInput {
	in := client.BackupTargetInput{Enabled: m.Enabled.ValueBool(), Endpoint: m.Endpoint.ValueString(), Region: m.Region.ValueString(),
		Bucket: m.Bucket.ValueString(), Prefix: m.Prefix.ValueString(), PathStyle: m.PathStyle.ValueBool(), AccessKeyID: m.AccessKeyID.ValueString(),
		CABundlePEM: m.CABundlePEM.ValueString(), AllowPrivateNetwork: m.AllowPrivateNetwork.ValueBool(), Interval: m.Interval.ValueString(),
		KeepLast: m.KeepLast.ValueInt64(), KeepDailyDays: m.KeepDailyDays.ValueInt64()}
	if secret {
		s := m.SecretAccessKey.ValueString()
		in.SecretAccessKey = &s
	}
	return in
}

func (m *backupTargetModel) fill(t *client.BackupTarget) {
	m.ID = types.StringValue("backup-target")
	m.Enabled = types.BoolValue(t.Enabled)
	m.Endpoint = types.StringValue(t.Endpoint)
	m.Region = types.StringValue(t.Region)
	m.Bucket = types.StringValue(t.Bucket)
	m.Prefix = types.StringValue(t.Prefix)
	m.PathStyle = types.BoolValue(t.PathStyle)
	m.AccessKeyID = types.StringValue(t.AccessKeyID)
	m.CABundlePEM = types.StringValue(t.CABundlePEM)
	m.AllowPrivateNetwork = types.BoolValue(t.AllowPrivateNetwork)
	secs := int64(0)
	if d, err := time.ParseDuration(t.Interval); err == nil {
		secs = int64(d / time.Second)
	}
	m.Interval = durationOf(m.Interval, secs)
	m.KeepLast = types.Int64Value(t.KeepLast)
	m.KeepDailyDays = types.Int64Value(t.KeepDailyDays)
}

func (r *backupTargetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan backupTargetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.PutBackupTarget(ctx, 0, plan.input(true))
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot create the backup target (if one exists, import it with `backup-target`)", err)
		return
	}
	plan.fill(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, t.Version)...)
}

func (r *backupTargetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state backupTargetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.GetBackupTarget(ctx)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read the backup target", err)
		return
	}
	state.fill(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, t.Version)...)
}

func (r *backupTargetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state backupTargetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := plan.input(!plan.SecretAccessKey.Equal(state.SecretAccessKey))
	t, err := r.client.PutBackupTarget(ctx, loadVersion(ctx, req.Private), in)
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot update the backup target", err)
		return
	}
	plan.fill(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(saveVersion(ctx, resp.Private, t.Version)...)
}

func (r *backupTargetResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.DeleteBackupTarget(ctx); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot delete the backup target", err)
	}
}

func (r *backupTargetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
