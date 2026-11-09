package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) executionBoundary(ctx context.Context, runID string, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy, authorization *spec.Authorization, approved bool, coord *coordinator) (spec.TargetSnapshot, error) {
	if err := coord.check(ctx); err != nil {
		return spec.TargetSnapshot{}, err
	}
	if err := e.checkPlan(ctx, p, v, policy, false); err != nil {
		return spec.TargetSnapshot{}, err
	}
	snapshot, err := e.currentCheckpoint(ctx, runID, p, v, policy)
	if err != nil {
		return spec.TargetSnapshot{}, err
	}
	_, err = e.authorize(p, policy, authorization, approved)
	return snapshot, err
}
