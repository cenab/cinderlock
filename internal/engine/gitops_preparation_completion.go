package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) gitOpsPreparationComplete(ctx context.Context, p spec.Plan, v *bundle.Verified, runID string) error {
	if err := e.verifyGitOpsPreparation(p, v); err != nil {
		return err
	}
	for _, seed := range p.Operations {
		binding, err := e.resolveSeedVolumeBinding(ctx, runID, seed, v, true)
		if err != nil {
			return err
		}
		if err := e.gitOpsSeedReceipt(ctx, runID, binding, nil); err != nil {
			return err
		}
		if err := e.fixturePodExclusivity(ctx, runID, seed.PVC); err != nil {
			return err
		}
	}
	return nil
}
