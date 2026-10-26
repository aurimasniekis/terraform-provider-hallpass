package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

var (
	_ resource.ResourceWithImportState = (*destinationCollectorResource)(nil)

	sshEd25519RE = regexp.MustCompile(`^\s*ssh-ed25519 AAAA[0-9A-Za-z+/]+=*(\s.*)?$`)
)

type destinationCollectorResource struct{ baseResource }

// NewDestinationCollectorResource returns the hallpass_destination_collector resource.
func NewDestinationCollectorResource() resource.Resource { return &destinationCollectorResource{} }

type destinationCollectorModel struct {
	ID          types.String `tfsdk:"id"`
	ServerID    types.String `tfsdk:"server_id"`
	Name        types.String `tfsdk:"name"`
	PublicKey   types.String `tfsdk:"public_key"`
	Fingerprint types.String `tfsdk:"fingerprint"`
}

func (r *destinationCollectorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_destination_collector"
}

func (r *destinationCollectorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Enrolls a destination audit collector (`hallpass-collector`) on one server: its Ed25519 public key " +
			"signs the batches of process and file records it sends. Its records can attach to every session on that server. " +
			"Destroying the resource revokes the key; a changed key (for example after reinstalling the collector) enrolls the " +
			"new key and revokes the old one. HallPass keeps the names of revoked collectors reserved on their server, so " +
			"leave `name` unset (it is then derived from the key) or change it together with the key. Import with the " +
			"collector ID.",
		Attributes: map[string]schema.Attribute{
			"id":        idAttribute("Collector ID (`dac_…`)."),
			"server_id": parentAttribute("Server ID (`srv_…`).", "srv"),
			"name": schema.StringAttribute{
				MarkdownDescription: "Name shown in the console (at most 64 characters, unique per server including revoked " +
					"collectors). Defaults to `collector-` and the first 12 hex digits of the key's SHA-256. Changing it forces a " +
					"new enrollment.",
				Optional: true, Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()},
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 64)},
			},
			"public_key": schema.StringAttribute{
				MarkdownDescription: "The collector's `ssh-ed25519` public key, as `hallpass-collector pubkey` prints it. Changing " +
					"it forces a new enrollment.",
				Required: true, PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.RegexMatches(sshEd25519RE, "must be an ssh-ed25519 public key")},
			},
			"fingerprint": computedString("SHA-256 fingerprint of the key."),
		},
	}
}

func (m *destinationCollectorModel) fill(d *client.DestinationCollector) {
	m.ID = types.StringValue(d.ID)
	m.ServerID = types.StringValue(d.ServerID)
	m.Name = types.StringValue(d.Name)
	m.Fingerprint = types.StringValue(d.Fingerprint)
	// Keep the configured spelling (a trailing comment) when it is the same key.
	if m.PublicKey.IsNull() || m.PublicKey.IsUnknown() || keyBody(m.PublicKey.ValueString()) != keyBody(d.PublicKey) {
		m.PublicKey = types.StringValue(d.PublicKey)
	}
}

// defaultCollectorName derives a name from the key, so a new key gets a new name (names of revoked collectors stay
// reserved).
func defaultCollectorName(key string) string {
	sum := sha256.Sum256([]byte(keyBody(key)))
	return "collector-" + hex.EncodeToString(sum[:])[:12]
}

// keyBody is "<type> <base64>" without the comment.
func keyBody(k string) string {
	f := strings.Fields(k)
	if len(f) < 2 {
		return k
	}
	return f[0] + " " + f[1]
}

func (r *destinationCollectorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan destinationCollectorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	if plan.Name.IsNull() || plan.Name.IsUnknown() {
		name = defaultCollectorName(plan.PublicKey.ValueString())
	}
	d, err := r.client.RegisterDestinationCollector(ctx, client.DestinationCollectorInput{ServerID: plan.ServerID.ValueString(),
		Name: name, PublicKey: strings.TrimSpace(plan.PublicKey.ValueString())})
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot enroll destination collector", err)
		return
	}
	plan.fill(d)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *destinationCollectorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state destinationCollectorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	d, err := r.client.GetDestinationCollector(ctx, state.ID.ValueString())
	if client.IsNotFound(err) || (err == nil && d.State != "active") {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "Cannot read destination collector", err)
		return
	}
	state.fill(d)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *destinationCollectorResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Every attribute forces replacement.
}

func (r *destinationCollectorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state destinationCollectorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeDestinationCollector(ctx, state.ID.ValueString(), "removed by Terraform"); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "Cannot revoke destination collector", err)
	}
}

func (r *destinationCollectorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
