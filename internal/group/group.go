package group

import (
	"context"
	"fmt"
	"github.com/cenab/cinderlock/internal/spec"
)

type Entry struct {
	ID            string            `json:"id"`
	Plan          string            `json:"plan"`
	Authorization string            `json:"authorization"`
	DependsOn     []string          `json:"dependsOn"`
	Requires      map[string]string `json:"requires,omitempty"`
}
type Group struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Entries    []Entry `json:"entries"`
}
type Item struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	RunID  string `json:"runID,omitempty"`
	Error  string `json:"error,omitempty"`
}
type Result struct {
	Items    []Item `json:"items"`
	Accepted bool   `json:"accepted"`
}

func Order(g Group) ([]Entry, error) {
	if g.APIVersion != spec.APIVersion || g.Kind != "ReleaseGroup" {
		return nil, spec.Err(2, "invalid release group")
	}
	if len(g.Entries) == 0 {
		return nil, spec.Err(2, "release group requires at least one application plan")
	}
	m := map[string]Entry{}
	for _, x := range g.Entries {
		if x.ID == "" || x.Plan == "" {
			return nil, spec.Err(2, "group entries require ID and plan")
		}
		if _, ok := m[x.ID]; ok {
			return nil, spec.Err(2, "duplicate group entry")
		}
		m[x.ID] = x
	}
	seen := map[string]int{}
	out := []Entry{}
	var visit func(string) error
	visit = func(id string) error {
		x, ok := m[id]
		if !ok {
			return fmt.Errorf("unknown dependency %s", id)
		}
		if seen[id] == 1 {
			return spec.Err(2, "group cycle")
		}
		if seen[id] == 2 {
			return nil
		}
		seen[id] = 1
		for _, dep := range x.DependsOn {
			if e := visit(dep); e != nil {
				return e
			}
		}
		for dependency, version := range x.Requires {
			if version == "" {
				return spec.Err(2, "group version constraint is empty")
			}
			found := false
			for _, dep := range x.DependsOn {
				if dep == dependency {
					found = true
				}
			}
			if !found {
				return spec.Err(2, "version constraint requires a direct group dependency")
			}
		}
		seen[id] = 2
		out = append(out, x)
		return nil
	}
	for _, x := range g.Entries {
		if e := visit(x.ID); e != nil {
			return nil, e
		}
	}
	return out, nil
}

func ValidatePlans(g Group, plans map[string]spec.Plan) error {
	order, err := Order(g)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range order {
		p, ok := plans[entry.ID]
		if !ok || p.Kind != "Plan" || !p.Executable || p.Metadata.Application == "" || p.TargetVersion == "" {
			return spec.Err(2, "group entry %s requires an executable application plan", entry.ID)
		}
		key := p.Snapshot.TargetID + "/" + p.Metadata.Application
		if seen[key] {
			return spec.Err(2, "group includes the same target/application more than once")
		}
		seen[key] = true
		for dependency, version := range entry.Requires {
			if plans[dependency].TargetVersion != version {
				return spec.Err(10, "group entry %s requires %s at %s", entry.ID, dependency, version)
			}
		}
	}
	return nil
}
func Apply(ctx context.Context, g Group, apply func(context.Context, Entry) (spec.RunResult, error)) (Result, error) {
	order, e := Order(g)
	if e != nil {
		return Result{}, e
	}
	r := Result{Items: []Item{}}
	for _, x := range order {
		if e := ctx.Err(); e != nil {
			return r, e
		}
		run, e := apply(ctx, x)
		item := Item{ID: x.ID, Status: run.State, RunID: run.RunID}
		if e != nil {
			item.Error = e.Error()
			r.Items = append(r.Items, item)
			for _, remaining := range order[len(r.Items):] {
				r.Items = append(r.Items, Item{ID: remaining.ID, Status: "not_started"})
			}
			return r, e
		}
		r.Items = append(r.Items, item)
	}
	r.Accepted = true
	return r, nil
}
