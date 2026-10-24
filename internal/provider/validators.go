package provider

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// canonicalCIDR requires a CIDR in its masked form (10.1.0.0/16, not 10.1.2.3/16): HallPass stores the masked form,
// and a different spelling would show a change on every plan.
type canonicalCIDR struct{}

func (canonicalCIDR) Description(context.Context) string {
	return "must be a CIDR in canonical form, e.g. 10.1.0.0/16"
}

func (v canonicalCIDR) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (canonicalCIDR) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CIDR", fmt.Sprintf("%q is not a CIDR such as 10.1.0.0/16", s))
		return
	}
	if m := p.Masked().String(); m != s {
		resp.Diagnostics.AddAttributeError(req.Path, "CIDR not in canonical form", fmt.Sprintf("write %q instead of %q", m, s))
	}
}
