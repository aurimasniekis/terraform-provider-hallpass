package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// Selectors pick agents, servers, roles or operators for policy rules, approver rules and notification routes. A
// selector matches the union of its clauses; an empty selector matches nothing, so `all = true` must be explicit.

type labelExprModel struct {
	Key      types.String `tfsdk:"key"`
	Operator types.String `tfsdk:"operator"`
	Values   types.Set    `tfsdk:"values"`
}

type labelSelectorModel struct {
	MatchLabels      types.Map        `tfsdk:"match_labels"`
	MatchExpressions []labelExprModel `tfsdk:"match_expressions"`
}

type subjectsModel struct {
	All         types.Bool          `tfsdk:"all"`
	Agents      types.Set           `tfsdk:"agents"`
	AgentGroups types.Set           `tfsdk:"agent_groups"`
	AgentLabels *labelSelectorModel `tfsdk:"agent_labels"`
}

type targetsModel struct {
	All          types.Bool          `tfsdk:"all"`
	Servers      types.Set           `tfsdk:"servers"`
	ServerGroups types.Set           `tfsdk:"server_groups"`
	ServerLabels *labelSelectorModel `tfsdk:"server_labels"`
}

type rolesModel struct {
	All        types.Bool          `tfsdk:"all"`
	Names      types.Set           `tfsdk:"names"`
	IDs        types.Set           `tfsdk:"ids"`
	RoleLabels *labelSelectorModel `tfsdk:"role_labels"`
}

type operatorsModel struct {
	All            types.Bool `tfsdk:"all"`
	Operators      types.Set  `tfsdk:"operators"`
	OperatorGroups types.Set  `tfsdk:"operator_groups"`
}

func allAttribute(what string) schema.BoolAttribute {
	return schema.BoolAttribute{
		MarkdownDescription: "Match every " + what + ", including ones created later.",
		Optional:            true, Computed: true, Default: booldefault.StaticBool(false),
	}
}

func clauseSet(desc string, v ...validator.String) schema.SetAttribute {
	return schema.SetAttribute{
		MarkdownDescription: desc,
		ElementType:         types.StringType,
		Optional:            true,
		Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(v...)},
	}
}

func labelSelectorAttribute(desc string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: desc + " Every `match_labels` pair and every expression must hold.",
		Optional:            true,
		Attributes: map[string]schema.Attribute{
			"match_labels": schema.MapAttribute{
				MarkdownDescription: "Labels that must have exactly these values.",
				ElementType:         types.StringType, Optional: true,
				Validators: []validator.Map{mapvalidator.SizeAtLeast(1)},
			},
			"match_expressions": schema.ListNestedAttribute{
				MarkdownDescription: "Label expressions.",
				Optional:            true,
				Validators:          []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"key": schema.StringAttribute{MarkdownDescription: "Label key.", Required: true},
					"operator": schema.StringAttribute{
						MarkdownDescription: "`In`, `NotIn`, `Exists` or `DoesNotExist`.", Required: true,
						Validators: []validator.String{stringvalidator.OneOf("In", "NotIn", "Exists", "DoesNotExist")},
					},
					"values": schema.SetAttribute{
						MarkdownDescription: "Values for `In` and `NotIn`.", ElementType: types.StringType, Optional: true,
						Validators: []validator.Set{setvalidator.SizeAtLeast(1)},
					},
				}},
			},
		},
	}
}

func subjectsAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: "Which agents the rule applies to.",
		Required:            true,
		Attributes: map[string]schema.Attribute{
			"all":          allAttribute("agent"),
			"agents":       clauseSet("Agent IDs (`agt_…`).", idValidator("agt")),
			"agent_groups": clauseSet("Agent group names."),
			"agent_labels": labelSelectorAttribute("Agents by label."),
		},
	}
}

func targetsAttribute(desc string, required bool) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: desc,
		Required:            required,
		Optional:            !required,
		Attributes: map[string]schema.Attribute{
			"all":           allAttribute("server and git remote"),
			"servers":       clauseSet("Server and git remote IDs (`srv_…`).", idValidator("srv")),
			"server_groups": clauseSet("Server group names."),
			"server_labels": labelSelectorAttribute("Servers by label."),
		},
	}
}

func rolesAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: "Which roles and access profiles.",
		Required:            true,
		Attributes: map[string]schema.Attribute{
			"all":         allAttribute("role"),
			"names":       clauseSet("Role or access profile names (on any matching server)."),
			"ids":         clauseSet("Role IDs (`rol_…`).", idValidator("rol")),
			"role_labels": labelSelectorAttribute("Roles by label."),
		},
	}
}

func operatorsAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: "Which operators may approve.",
		Required:            true,
		Attributes: map[string]schema.Attribute{
			"all":             allAttribute("operator"),
			"operators":       clauseSet("Operator IDs (`opr_…`); see the `hallpass_operator` data source.", idValidator("opr")),
			"operator_groups": clauseSet("Operator group names (for example from single sign-on group mappings)."),
		},
	}
}

func (m *labelSelectorModel) toAPI(ctx context.Context, diags *diag.Diagnostics) *client.LabelSelector {
	if m == nil {
		return nil
	}
	out := &client.LabelSelector{}
	if !m.MatchLabels.IsNull() {
		out.MatchLabels = stringMapOf(ctx, m.MatchLabels, diags)
	}
	for _, e := range m.MatchExpressions {
		r := client.LabelRequirement{Key: e.Key.ValueString(), Operator: e.Operator.ValueString()}
		if !e.Values.IsNull() {
			r.Values = stringsOf(ctx, e.Values, diags)
		}
		out.MatchExpressions = append(out.MatchExpressions, r)
	}
	return out
}

func labelSelectorFrom(ls *client.LabelSelector) *labelSelectorModel {
	if ls == nil || (len(ls.MatchLabels) == 0 && len(ls.MatchExpressions) == 0) {
		return nil
	}
	m := &labelSelectorModel{MatchLabels: optMapOf(ls.MatchLabels)}
	for _, e := range ls.MatchExpressions {
		m.MatchExpressions = append(m.MatchExpressions, labelExprModel{Key: types.StringValue(e.Key),
			Operator: types.StringValue(e.Operator), Values: optSetOf(e.Values)})
	}
	return m
}

func (m *subjectsModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.SubjectSelector {
	if m == nil {
		return client.SubjectSelector{}
	}
	return client.SubjectSelector{All: m.All.ValueBool(), Agents: optStrings(ctx, m.Agents, diags),
		AgentGroups: optStrings(ctx, m.AgentGroups, diags), AgentLabels: m.AgentLabels.toAPI(ctx, diags)}
}

func subjectsFrom(s client.SubjectSelector) *subjectsModel {
	return &subjectsModel{All: types.BoolValue(s.All), Agents: optSetOf(s.Agents), AgentGroups: optSetOf(s.AgentGroups),
		AgentLabels: labelSelectorFrom(s.AgentLabels)}
}

func (m *targetsModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.TargetSelector {
	if m == nil {
		return client.TargetSelector{}
	}
	return client.TargetSelector{All: m.All.ValueBool(), Servers: optStrings(ctx, m.Servers, diags),
		ServerGroups: optStrings(ctx, m.ServerGroups, diags), ServerLabels: m.ServerLabels.toAPI(ctx, diags)}
}

func targetsFrom(s client.TargetSelector) *targetsModel {
	return &targetsModel{All: types.BoolValue(s.All), Servers: optSetOf(s.Servers), ServerGroups: optSetOf(s.ServerGroups),
		ServerLabels: labelSelectorFrom(s.ServerLabels)}
}

func (m *rolesModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.RoleSelector {
	if m == nil {
		return client.RoleSelector{}
	}
	return client.RoleSelector{All: m.All.ValueBool(), Names: optStrings(ctx, m.Names, diags), IDs: optStrings(ctx, m.IDs, diags),
		RoleLabels: m.RoleLabels.toAPI(ctx, diags)}
}

func rolesFrom(s client.RoleSelector) *rolesModel {
	return &rolesModel{All: types.BoolValue(s.All), Names: optSetOf(s.Names), IDs: optSetOf(s.IDs), RoleLabels: labelSelectorFrom(s.RoleLabels)}
}

func (m *operatorsModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.OperatorSelector {
	if m == nil {
		return client.OperatorSelector{}
	}
	return client.OperatorSelector{All: m.All.ValueBool(), Operators: optStrings(ctx, m.Operators, diags),
		OperatorGroups: optStrings(ctx, m.OperatorGroups, diags)}
}

func operatorsFrom(s client.OperatorSelector) *operatorsModel {
	return &operatorsModel{All: types.BoolValue(s.All), Operators: optSetOf(s.Operators), OperatorGroups: optSetOf(s.OperatorGroups)}
}

// optStrings is stringsOf with nil for a null set (so the clause is left out of the request).
func optStrings(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	return stringsOf(ctx, s, diags)
}
