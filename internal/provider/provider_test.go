package provider

import (
	"context"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func errRE(parts ...string) *regexp.Regexp {
	re := ""
	for i, p := range parts {
		if i > 0 {
			re += `[\s\S]*`
		}
		re += regexp.QuoteMeta(p)
	}
	return regexp.MustCompile(re)
}

func TestSchemasAreValid(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	var ps fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &ps)
	if d := ps.Schema.ValidateImplementation(ctx); d.HasError() {
		t.Fatalf("provider schema: %v", d)
	}
	seen := map[string]bool{}
	for _, f := range p.Resources(ctx) {
		r := f()
		var md fwresource.MetadataResponse
		r.Metadata(ctx, fwresource.MetadataRequest{ProviderTypeName: "hallpass"}, &md)
		if seen[md.TypeName] {
			t.Fatalf("duplicate resource %s", md.TypeName)
		}
		seen[md.TypeName] = true
		var sr fwresource.SchemaResponse
		r.Schema(ctx, fwresource.SchemaRequest{}, &sr)
		if sr.Diagnostics.HasError() {
			t.Fatalf("%s: %v", md.TypeName, sr.Diagnostics)
		}
		if d := sr.Schema.ValidateImplementation(ctx); d.HasError() {
			t.Fatalf("%s: %v", md.TypeName, d)
		}
		if _, ok := sr.Schema.Attributes["id"]; !ok {
			t.Errorf("%s has no id attribute", md.TypeName)
		}
		if sr.Schema.MarkdownDescription == "" {
			t.Errorf("%s has no description", md.TypeName)
		}
	}
	if len(seen) != 17 {
		t.Errorf("got %d resources, want 17", len(seen))
	}
	for _, f := range p.DataSources(ctx) {
		d := f()
		var md datasource.MetadataResponse
		d.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "hallpass"}, &md)
		var sr datasource.SchemaResponse
		d.Schema(ctx, datasource.SchemaRequest{}, &sr)
		if diags := sr.Schema.ValidateImplementation(ctx); diags.HasError() {
			t.Fatalf("%s: %v", md.TypeName, diags)
		}
	}
}

func TestDurations(t *testing.T) {
	for secs, want := range map[int64]string{14400: "4h", 5400: "1h30m", 90: "1m30s", 30: "30s", 1800: "30m"} {
		if got := formatDuration(secs); got != want {
			t.Errorf("formatDuration(%d) = %q, want %q", secs, got, want)
		}
	}
	if got := durationOf(types.StringValue("240m"), 14400); got.ValueString() != "240m" {
		t.Errorf("equivalent configured value not kept: %v", got)
	}
	if got := durationOf(types.StringValue("240m"), 7200); got.ValueString() != "2h" {
		t.Errorf("changed value: %v", got)
	}
	if got := durationOf(types.StringNull(), 0); !got.IsNull() {
		t.Errorf("zero: %v", got)
	}
	if seconds(types.StringValue("1h30m")) != 5400 {
		t.Error("seconds")
	}
}

func TestCanonicalCIDR(t *testing.T) {
	for in, ok := range map[string]bool{"10.1.0.0/16": true, "10.1.2.3/16": false, "2001:db8::/32": true, "nope": false} {
		var resp validator.StringResponse
		canonicalCIDR{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("x"), ConfigValue: types.StringValue(in)}, &resp)
		if resp.Diagnostics.HasError() == ok {
			t.Errorf("%s: %v", in, resp.Diagnostics)
		}
	}
}

func TestSplitID(t *testing.T) {
	if p, err := splitID("srv_1/hid_2", 2, "<server_id>/<id>"); err != nil || p[0] != "srv_1" || p[1] != "hid_2" {
		t.Fatalf("got %v %v", p, err)
	}
	for _, bad := range []string{"", "x", "a/", "/b", "a/b/c"} {
		if _, err := splitID(bad, 2, "<server_id>/<id>"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestProviderConfigValidation(t *testing.T) {
	t.Setenv(EnvEndpoint, "")
	t.Setenv(EnvToken, "")
	const ds = `
data "hallpass_gateway_host_keys" "x" {}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: `provider "hallpass" { endpoint = "https://hallpass.example.com" }` + ds, ExpectError: errRE("Missing HallPass API token")},
			{Config: `provider "hallpass" { token = "hallpass_at_x" }` + ds, ExpectError: errRE("Missing HallPass endpoint")},
			{
				Config:      "provider \"hallpass\" {\n  endpoint = \"https://hallpass.example.com\"\n  token = \"porch_at_abc\"\n}\n" + ds,
				ExpectError: errRE("Invalid HallPass API token", `starting with "hallpass_at_"`),
			},
			{
				Config: "provider \"hallpass\" {\n  endpoint = \"hallpass.example.com\"\n  token = \"hallpass_at_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG\"\n}\n" +
					ds,
				ExpectError: errRE("Cannot configure the HallPass client", "endpoint must be an absolute http(s) URL"),
			},
		},
	})
}
