package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
)

// Delayed data handoffs re-observe completed workers as well as uncertain ones.
func (e *Engine) gitOpsTerminalWorkers(ctx context.Context, runID string, successful bool) error {
	if err := e.Store.WorkerProtocol(ctx, runID); err != nil {
		return spec.Err(13, "%v", err)
	}
	attempts, err := e.Store.Operations(ctx, runID)
	if err != nil {
		return err
	}
	workers, err := e.Store.Workers(ctx, runID)
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		kind := journalKind(attempt.Intent)
		if successful && attempt.State != "complete" {
			return spec.Err(13, "data predecessor has an incomplete operation receipt")
		}
		if !jobOperation(kind) && kind != "check" && kind != "gitops-model-verification" {
			if attempt.State != "complete" {
				return spec.Err(13, "unresolved non-Job effects cannot transfer a data gate")
			}
			continue
		}
		native := false
		if kind == "seed" {
			var op spec.Operation
			if spec.Decode(attempt.Intent, &op) != nil {
				return spec.Err(13, "original seed intent is unavailable")
			}
			native = len(op.Command) == 0
		}
		found := false
		for _, worker := range workers {
			if worker.StepID != attempt.StepID || worker.Attempt != attempt.Attempt {
				continue
			}
			job, err := e.workerJob(ctx, worker)
			if err != nil {
				return err
			}
			status := workerStatus(job)
			if status != "complete" && status != "failed" || successful && status != "complete" {
				return spec.Err(13, "an original predecessor Job is not confirmed terminal with the required outcome")
			}
			if worker.Role == attempt.StepID {
				found = true
				if native {
					status, err := e.modelReceiverStatus(ctx, worker)
					if err != nil || status != "complete" && status != "failed" || successful && status != "complete" {
						return spec.Err(13, "the original native receiver Pod is not confirmed terminal")
					}
				}
			}
		}
		if !found && !(kind == "check" && !successful && fixtureMainNotStarted(attempt)) {
			return spec.Err(13, "original predecessor worker identity is unavailable; termination cannot be inferred")
		}
	}
	return nil
}
