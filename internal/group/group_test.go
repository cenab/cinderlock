package group

import (
	"context"
	"errors"
	"github.com/cenab/cinderlock/internal/spec"
	"testing"
)

func TestGroupStopsAndPreservesPartialState(t *testing.T) {
	g := Group{APIVersion: spec.APIVersion, Kind: "ReleaseGroup", Entries: []Entry{{ID: "a", Plan: "a"}, {ID: "b", Plan: "b", DependsOn: []string{"a"}}, {ID: "c", Plan: "c", DependsOn: []string{"b"}}}}
	n := 0
	r, e := Apply(context.Background(), g, func(_ context.Context, x Entry) (spec.RunResult, error) {
		n++
		if x.ID == "b" {
			return spec.RunResult{State: "needs_reconciliation"}, errors.New("uncertain")
		}
		return spec.RunResult{State: "succeeded"}, nil
	})
	if e == nil || n != 2 || r.Accepted || len(r.Items) != 3 || r.Items[2].Status != "not_started" {
		t.Fatal(r, e)
	}
}
func TestGroupRejectsCycle(t *testing.T) {
	_, e := Order(Group{APIVersion: spec.APIVersion, Kind: "ReleaseGroup", Entries: []Entry{{ID: "a", Plan: "a", DependsOn: []string{"b"}}, {ID: "b", Plan: "b", DependsOn: []string{"a"}}}})
	if e == nil {
		t.Fatal("cycle accepted")
	}
}

func TestEmptyGroupCannotBeAccepted(t *testing.T) {
	r, err := Apply(context.Background(), Group{APIVersion: spec.APIVersion, Kind: "ReleaseGroup"}, func(context.Context, Entry) (spec.RunResult, error) {
		t.Fatal("unexpected execution")
		return spec.RunResult{}, nil
	})
	if err == nil || r.Accepted {
		t.Fatal("empty release group accepted")
	}
}

func TestGroupVersionConstraintsAreCheckedBeforeExecution(t *testing.T) {
	g := Group{APIVersion: spec.APIVersion, Kind: "ReleaseGroup", Entries: []Entry{{ID: "database", Plan: "db.json"}, {ID: "api", Plan: "api.json", DependsOn: []string{"database"}, Requires: map[string]string{"database": "2.0.0"}}}}
	plans := map[string]spec.Plan{}
	for _, name := range []string{"api", "database"} {
		p := spec.Plan{Header: spec.NewHeader("Plan"), Executable: true, TargetVersion: "1.0.0", Snapshot: spec.TargetSnapshot{TargetID: "target"}}
		p.Metadata.Application = name
		plans[name] = p
	}
	if err := ValidatePlans(g, plans); err == nil {
		t.Fatal("incompatible dependency accepted")
	}
	p := plans["database"]
	p.TargetVersion = "2.0.0"
	plans["database"] = p
	if err := ValidatePlans(g, plans); err != nil {
		t.Fatal(err)
	}
	g.Entries[1].DependsOn = nil
	if err := ValidatePlans(g, plans); err == nil {
		t.Fatal("unordered version dependency accepted")
	}
}
