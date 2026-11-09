package engine

import (
	"slices"

	"github.com/cenab/cinderlock/internal/spec"
)

type gitOpsDataCut struct {
	transition    spec.Transition
	before, after []spec.Operation
	source        string
}

func gitOpsDataSelection(r spec.Release, from string) (gitOpsDataCut, error) {
	var cut gitOpsDataCut
	if r.Spec.Deployment.Type != "gitops" || r.Spec.Deployment.GitOps == nil || r.Spec.Deployment.GitOps.Data == nil {
		return cut, spec.Err(10, "mutable GitOps execution requires explicit signed data procedures")
	}
	matched := false
	for _, t := range r.Spec.Transitions {
		if t.FromRelease != from {
			continue
		}
		if matched || len(t.IntermediateReleases) != 0 {
			return cut, spec.Err(10, "GitOps data transition is ambiguous or requires intermediate releases")
		}
		cut.transition, matched = t, true
	}
	if !matched || len(cut.transition.Operations) > 64 {
		return cut, spec.Err(10, "GitOps data needs a supported exact source transition with at most 64 operations")
	}
	selected := map[string]spec.Operation{}
	ordered := []spec.Operation{}
	for _, id := range cut.transition.Operations {
		if _, exists := selected[id]; exists {
			return cut, spec.Err(12, "GitOps data transition repeats an operation")
		}
		at := slices.IndexFunc(r.Spec.Operations, func(o spec.Operation) bool { return o.ID == id })
		if at < 0 {
			return cut, spec.Err(12, "GitOps data transition references a missing operation")
		}
		selected[id] = r.Spec.Operations[at]
		ordered = append(ordered, r.Spec.Operations[at])
	}
	for _, op := range ordered {
		for _, dep := range op.DependsOn {
			if _, ok := selected[dep]; !ok {
				return cut, spec.Err(10, "GitOps data dependency is outside its signed selected transition")
			}
		}
	}
	var err error
	ordered, err = gitOpsOperationOrder(ordered)
	if err != nil {
		return cut, err
	}
	ancestors := map[string]map[string]bool{}
	covered := map[string]bool{}
	fixtures := map[string]bool{}
	for _, c := range r.Spec.Checks {
		for _, asset := range c.Fixtures {
			fixtures[asset] = true
		}
	}
	for _, op := range ordered {
		parents := map[string]bool{}
		for _, dep := range op.DependsOn {
			parents[dep] = true
			for id := range ancestors[dep] {
				parents[id] = true
			}
		}
		ancestors[op.ID] = parents
		if op.Type == "gitops" {
			if cut.source != "" {
				return cut, spec.Err(10, "GitOps data requires exactly one source-adoption marker")
			}
			cut.source = op.ID
		}
		covered[op.ID] = op.Type == "import" || op.Type == "seed" && !fixtures[op.Asset] && len(op.Command) == 0
	}
	if cut.source == "" {
		return cut, spec.Err(10, "GitOps data transition has no source-adoption marker")
	}
	for _, op := range ordered {
		if covered[op.ID] {
			for _, dep := range op.DependsOn {
				if !covered[dep] {
					return cut, spec.Err(10, "separate artifact preparation depends on a data or adoption phase")
				}
			}
			continue
		}
		switch op.Type {
		case "gitops":
			continue
		case "seed":
			if !fixtures[op.Asset] || len(op.Command) != 0 || ancestors[cut.source][op.ID] {
				return cut, spec.Err(10, "acceptance fixtures must belong to the post-adoption check phase")
			}
			cut.after = append(cut.after, op)
		case "job", "backup", "migrate", "reindex":
			if ancestors[cut.source][op.ID] {
				cut.before = append(cut.before, op)
			} else if ancestors[op.ID][cut.source] {
				cut.after = append(cut.after, op)
			} else {
				return cut, spec.Err(10, "authored data procedure has no unambiguous side of source adoption")
			}
		default:
			return cut, spec.Err(10, "GitOps data cannot select a second resource writer or unsupported operation")
		}
	}
	c := r.Spec.Deployment.GitOps.Data
	has := func(ops []spec.Operation, id string) bool {
		return id != "" && slices.ContainsFunc(ops, func(o spec.Operation) bool { return o.ID == id })
	}
	if from == "install" {
		if len(cut.before) != 0 || c.Resume != "" && !has(cut.after, c.Resume) {
			return cut, spec.Err(10, "initial data adoption cannot run pre-adoption upgrades or omit its declared resume procedure")
		}
	} else {
		if !has(cut.before, c.Quiesce) || !has(cut.before, c.Backup) || !has(cut.after, c.Resume) || !ancestors[c.Backup][c.Quiesce] || !ancestors[c.Resume][cut.source] {
			return cut, spec.Err(10, "data upgrades require signed quiesce, backup and post-adoption resume procedures")
		}
		for _, op := range cut.before {
			if op.ID != c.Quiesce && op.ID != c.Backup && !ancestors[op.ID][c.Backup] {
				return cut, spec.Err(10, "pre-adoption mutations must follow the declared quiescence and backup")
			}
		}
	}
	return cut, nil
}

func gitOpsDataRecoverySelection(recovery spec.Recovery) ([]spec.Operation, error) {
	c := recovery.GitOpsData
	if c == nil || c.Quiesce == "" || c.Resume == "" || c.Backup != "" || len(recovery.Operations) > 64 {
		return nil, spec.Err(10, "same-source restore requires bounded explicit quiesce/resume procedures and preserves the original backup")
	}
	ordered, err := gitOpsOperationOrder(recovery.Operations)
	if err != nil {
		return nil, err
	}
	fixtures := map[string]bool{}
	for _, check := range recovery.Checks {
		for _, asset := range check.Fixtures {
			fixtures[asset] = true
		}
	}
	ancestors := map[string]map[string]bool{}
	for _, op := range ordered {
		parents := map[string]bool{}
		for _, dep := range op.DependsOn {
			if _, exists := ancestors[dep]; !exists {
				return nil, spec.Err(12, "restore dependency is outside the selected recovery recipe")
			}
			parents[dep] = true
			for id := range ancestors[dep] {
				parents[id] = true
			}
		}
		ancestors[op.ID] = parents
	}
	restored := false
	for _, op := range ordered {
		if op.Type == "seed" {
			if !fixtures[op.Asset] || len(op.Command) != 0 || op.PVC == c.PVC {
				return nil, spec.Err(10, "restore seeds must be dedicated native same-run acceptance fixtures")
			}
			continue
		}
		if !isJob(op.Type) {
			return nil, spec.Err(10, "data restore cannot select another desired-state writer or unsupported operation")
		}
		if op.ID == c.Quiesce || op.ID == c.Resume {
			continue
		}
		if !ancestors[op.ID][c.Quiesce] {
			return nil, spec.Err(10, "restore operations must follow the signed write barrier")
		}
		if op.PVC != "" {
			if op.PVC != c.PVC || !ancestors[c.Resume][op.ID] {
				return nil, spec.Err(10, "mutable restore operations must precede the signed resume procedure on the same claim")
			}
			restored = true
		}
	}
	if !restored || !ancestors[c.Resume][c.Quiesce] {
		return nil, spec.Err(10, "restore lacks an explicit mutable operation between quiesce and resume")
	}
	return ordered, nil
}
