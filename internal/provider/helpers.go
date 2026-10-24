package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// privateState is the subset of the framework's private state API used to keep the resource version out of the
// visible schema.
type privateState interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

const versionKey = "version"

// saveVersion stores the resource version (sent as If-Match on the next change) in private state.
func saveVersion(ctx context.Context, p privateState, version int64) diag.Diagnostics {
	if p == nil || version <= 0 {
		return nil
	}
	b, _ := json.Marshal(version)
	return p.SetKey(ctx, versionKey, b)
}

// loadVersion returns the stored version (0 when unknown).
func loadVersion(ctx context.Context, p privateState) int64 {
	if p == nil {
		return 0
	}
	b, diags := p.GetKey(ctx, versionKey)
	if diags.HasError() || len(b) == 0 {
		return 0
	}
	var v int64
	if json.Unmarshal(b, &v) != nil {
		return 0
	}
	return v
}

// configureClient extracts the API client from provider data.
func configureClient(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", data))
		return nil
	}
	return c
}

// baseResource carries the client for every resource.
type baseResource struct {
	client *client.Client
}

func (b *baseResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := configureClient(req.ProviderData, &resp.Diagnostics); c != nil {
		b.client = c
	}
}

// baseDataSource carries the client for every data source.
type baseDataSource struct {
	client *client.Client
}

func (b *baseDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if c := configureClient(req.ProviderData, &resp.Diagnostics); c != nil {
		b.client = c
	}
}

// apiError adds an API error as a diagnostic. The message carries HallPass's problem code, title and field errors.
func apiError(diags *diag.Diagnostics, summary string, err error) {
	diags.AddError(summary, err.Error())
}

// splitID splits a composite import ID into exactly n non-empty parts separated by "/".
func splitID(id string, n int, format string) ([]string, error) {
	parts := strings.Split(id, "/")
	if len(parts) != n || slices.Contains(parts, "") {
		return nil, fmt.Errorf("expected an import ID of the form %q, got %q", format, id)
	}
	return parts, nil
}

// setOf converts strings to a types.Set (never null).
func setOf(ss []string) types.Set {
	vals := make([]attr.Value, 0, len(ss))
	for _, s := range ss {
		vals = append(vals, types.StringValue(s))
	}
	return types.SetValueMust(types.StringType, vals)
}

// optSetOf converts strings to a types.Set, null when empty (for optional selector clauses).
func optSetOf(ss []string) types.Set {
	if len(ss) == 0 {
		return types.SetNull(types.StringType)
	}
	return setOf(ss)
}

// stringsOf converts a set or list of strings ([] for null/unknown), sorted.
func stringsOf(ctx context.Context, v interface {
	IsNull() bool
	IsUnknown() bool
	ElementsAs(context.Context, any, bool) diag.Diagnostics
}, diags *diag.Diagnostics) []string {
	out := []string{}
	if v.IsNull() || v.IsUnknown() {
		return out
	}
	diags.Append(v.ElementsAs(ctx, &out, false)...)
	slices.Sort(out)
	return out
}

// mapOf converts a string map to types.Map (never null).
func mapOf(m map[string]string) types.Map {
	vals := make(map[string]attr.Value, len(m))
	for k, v := range m {
		vals[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, vals)
}

// optMapOf converts a string map to types.Map, null when empty.
func optMapOf(m map[string]string) types.Map {
	if len(m) == 0 {
		return types.MapNull(types.StringType)
	}
	return mapOf(m)
}

// stringMapOf converts a types.Map ({} for null/unknown).
func stringMapOf(ctx context.Context, m types.Map, diags *diag.Diagnostics) map[string]string {
	out := map[string]string{}
	if m.IsNull() || m.IsUnknown() {
		return out
	}
	diags.Append(m.ElementsAs(ctx, &out, false)...)
	return out
}

// optString maps "" to null.
func optString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

// Durations are written as Go durations ("30m", "4h") and sent as seconds.

var durationRE = regexp.MustCompile(`^([0-9]+(\.[0-9]+)?(h|m|s))+$`)

func durationValidator() validator.String {
	return stringvalidator.RegexMatches(durationRE, `must be a duration such as "30m", "4h" or "1h30m"`)
}

// seconds parses a configured duration (0 for null/unknown/empty).
func seconds(v types.String) int64 {
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return 0
	}
	d, err := time.ParseDuration(v.ValueString())
	if err != nil {
		return 0
	}
	return int64(d / time.Second)
}

// durationOf renders API seconds, keeping the prior value when it means the same duration (so "240m" in the
// configuration is not rewritten to "4h").
func durationOf(prior types.String, secs int64) types.String {
	if secs == 0 {
		if !prior.IsNull() && !prior.IsUnknown() && seconds(prior) == 0 && prior.ValueString() != "" {
			return prior
		}
		return types.StringNull()
	}
	if !prior.IsNull() && !prior.IsUnknown() && seconds(prior) == secs {
		return prior
	}
	return types.StringValue(formatDuration(secs))
}

// formatDuration renders seconds compactly: 14400 → "4h", 5400 → "1h30m", 90 → "1m30s".
func formatDuration(secs int64) string {
	var b strings.Builder
	for _, u := range []struct {
		n    int64
		unit string
	}{{3600, "h"}, {60, "m"}, {1, "s"}} {
		if secs >= u.n {
			b.WriteString(strconv.FormatInt(secs/u.n, 10) + u.unit)
			secs %= u.n
		}
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}

// aliasRE is HallPass's alias syntax; reserved gateway words are refused by the API.
var (
	aliasRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	nameRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
)

func aliasValidators() []validator.String {
	return []validator.String{stringvalidator.RegexMatches(aliasRE,
		"must start with a lowercase letter, then lowercase letters, digits or '-', not end in '-' (1-63 characters)")}
}

func nameValidators() []validator.String {
	return []validator.String{stringvalidator.RegexMatches(nameRE,
		"must be lowercase letters, digits, '.', '_' or '-', starting and ending with a letter or digit (1-64 characters)")}
}

// idValidator checks that a value is a HallPass ID with the given prefix.
func idValidator(prefix string) validator.String {
	return stringvalidator.RegexMatches(regexp.MustCompile(`^`+prefix+`_[0-9a-z]{10,40}$`), "must be a HallPass ID starting with "+prefix+"_")
}

// Common schema attributes.

func idAttribute(desc string) schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: desc,
		Computed:            true,
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func parentAttribute(desc, prefix string) schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: desc + " Changing it forces a new resource.",
		Required:            true,
		PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		Validators:          []validator.String{idValidator(prefix)},
	}
}

func computedString(desc string) schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: desc,
		Computed:            true,
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}
