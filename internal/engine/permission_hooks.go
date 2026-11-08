package engine

import (
	"context"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) addPermissionFindings(ctx context.Context, plan *spec.Plan, objects []map[string]any) {
	findings := e.PermissionFindings(ctx, *plan, objects)
	plan.Findings = append(plan.Findings, findings...)
	for _, finding := range findings {
		if finding.Severity == "blocker" {
			plan.Executable = false
		}
	}
}
