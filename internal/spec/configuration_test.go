package spec

import (
	"strings"
	"testing"
)

func TestConfigurationOwnershipRejectsNonAdjacentParentOverlap(t *testing.T) {
	deployment := Deployment{Configuration: &ConfigurationContract{Version: 1, Fields: []ConfigurationField{
		{Path: "auth", Owner: "site", Type: "object"},
		{Path: "auth-extra", Owner: "site", Type: "string"},
		{Path: "auth.token", Owner: "vendor", Type: "string"},
	}}}
	if err := ValidateConfigurationContract(deployment); err == nil {
		t.Fatal("parent object ownership overlaps a protected child despite intervening lexical sibling")
	}
}

func TestConfigurationOwnershipRequiresExactGeneratedBinding(t *testing.T) {
	base := Deployment{ImageBindings: []ImageBinding{{Asset: "app", ValuesPath: "runtime.image"}}, Configuration: &ConfigurationContract{Version: 1, Fields: []ConfigurationField{
		{Path: "runtime.image", Owner: "generated", Type: "string", Required: true},
		{Path: "tenant.name", Owner: "site", Type: "string"},
	}}}
	if err := ValidateConfigurationContract(base); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Deployment)
	}{
		{"duplicate-binding", func(d *Deployment) { d.ImageBindings = append(d.ImageBindings, d.ImageBindings[0]) }},
		{"generated-subtree", func(d *Deployment) {
			d.Configuration.Fields[0].Path = "runtime"
			d.Configuration.Fields[0].Type = "object"
		}},
		{"site-image", func(d *Deployment) { d.Configuration.Fields[0].Owner = "site" }},
		{"generated-unknown", func(d *Deployment) { d.Configuration.Fields[1].Owner = "generated" }},
		{"float-contract", func(d *Deployment) { d.Configuration.Fields[1].Type = "number" }},
		{"array-index", func(d *Deployment) { d.Configuration.Fields[1].Path = "tenant[0].name" }},
		{"unbounded-depth", func(d *Deployment) { d.Configuration.Fields[1].Path = strings.Repeat("a.", 16) + "name" }},
		{"duplicate-field", func(d *Deployment) {
			d.Configuration.Fields = append(d.Configuration.Fields, d.Configuration.Fields[1])
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.ImageBindings = append([]ImageBinding(nil), base.ImageBindings...)
			candidate.Configuration = &ConfigurationContract{Version: 1, Fields: append([]ConfigurationField(nil), base.Configuration.Fields...)}
			test.change(&candidate)
			if err := ValidateConfigurationContract(candidate); err == nil {
				t.Fatal("invalid ownership contract was accepted")
			}
		})
	}
}
