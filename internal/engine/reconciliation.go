package engine

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) Resume(ctx context.Context, runID string, v *bundle.Verified, policy spec.TrustPolicy, a *spec.Authorization, approved bool) (spec.RunResult, error) {
	if err := e.Store.WorkerProtocol(ctx, runID); err != nil {
		return spec.RunResult{}, spec.Err(13, "%v", err)
	}
	record, err := e.Store.Run(ctx, runID)
	if err != nil {
		return spec.RunResult{}, err
	}
	var p spec.Plan
	if err := spec.Decode(record.Plan, &p); err != nil {
		return spec.RunResult{}, err
	}
	if digest, err := spec.Digest(p); err != nil || digest != record.PlanDigest {
		return spec.RunResult{}, spec.Err(13, "stored plan differs from its admitted digest; reconcile journal integrity before execution")
	}
	if !record.Active {
		return spec.RunResult{}, spec.Err(10, "run is already terminal; do not replay it")
	}
	if err := e.checkPlan(ctx, p, v, policy, false); err != nil {
		return spec.RunResult{}, err
	}
	nonce, err := e.authorize(p, policy, a, approved)
	if err != nil {
		return spec.RunResult{}, err
	}
	if p.SourceRun != "" {
		if _, _, err := e.handoffSource(ctx, record, p); err != nil {
			return spec.RunResult{}, err
		}
	} else if err := e.verifyClusterRecord(ctx, runID, record.PlanDigest); err != nil {
		return spec.RunResult{}, err
	}
	coord, err := e.acquire(ctx, runID, p.SourceRun)
	if err != nil {
		return spec.RunResult{}, err
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = coord.release(c)
	}()
	if err := e.Store.ConsumeAuthorization(ctx, nonce, record.PlanDigest, runID, p.PolicyDigest, authorizationExpiry(a)); err != nil {
		return spec.RunResult{}, err
	}
	if p.SourceRun != "" {
		if err := e.completeHandoff(ctx, record, p); err != nil {
			return spec.RunResult{}, err
		}
	}
	beforeVerification := func() error {
		_, err := e.executionBoundary(ctx, runID, p, v, policy, a, approved, coord)
		return err
	}
	operations, err := e.Store.Operations(ctx, runID)
	if err != nil {
		return spec.RunResult{}, err
	}
	for _, attempt := range operations {
		if attempt.State != "intent" && attempt.State != "uncertain" {
			continue
		}
		if journalKind(attempt.Intent) == "check" {
			if err := e.resumeCheck(ctx, p, attempt); err != nil {
				return spec.RunResult{}, err
			}
			continue
		}
		if journalKind(attempt.Intent) == "gitops-model-verification" {
			if err := e.reconcileGitOpsModelVerification(ctx, p, v, attempt); err != nil {
				return spec.RunResult{}, err
			}
			continue
		}
		var op spec.Operation
		if err := json.Unmarshal(attempt.Intent, &op); err != nil {
			return spec.RunResult{}, err
		}
		matched := false
		for _, planned := range p.Operations {
			if planned.ID != attempt.StepID {
				continue
			}
			a, _ := spec.Digest(struct {
				Value any `json:"value"`
			}{planned})
			b, _ := spec.Digest(struct {
				Value any `json:"value"`
			}{op})
			matched = a == b
		}
		if !matched {
			return spec.RunResult{}, spec.Err(13, "durable operation intent differs from the signed plan; reconcile journal integrity before execution")
		}
		if p.Kind == "ArtifactsPlan" && op.Type == "import" {
			if err := coord.check(ctx); err != nil {
				return spec.RunResult{}, err
			}
			before, err := e.currentCheckpoint(ctx, runID, p, v, policy)
			if err != nil {
				return spec.RunResult{}, err
			}
			if err = e.checkPlan(ctx, p, v, policy, false); err != nil {
				return spec.RunResult{}, err
			}
			if _, err = e.authorize(p, policy, a, approved); err != nil {
				return spec.RunResult{}, err
			}
			external, err := e.operation(ctx, p, runID, op, v, policy, beforeVerification)
			if err != nil {
				return spec.RunResult{}, err
			}
			if _, err = e.advanceCheckpoint(ctx, runID, p, v, policy, op, before); err != nil {
				return spec.RunResult{}, err
			}
			step := spec.StepResult{ID: op.ID, Attempt: attempt.Attempt, Status: "pass", FinishedAt: spec.Now(), ExternalID: external}
			if err = e.Store.Complete(ctx, attempt, "complete", step); err != nil {
				return spec.RunResult{}, err
			}
			if err = e.clusterRecord(ctx, runID, record.PlanDigest, "complete", step); err != nil {
				return spec.RunResult{}, err
			}
			continue
		}
		if !jobOperation(op.Type) {
			return spec.RunResult{}, spec.Err(13, "uncertain %s needs an application-specific reviewed recovery plan", op.Type)
		}
		if op.Type == "seed" && len(op.Command) == 0 {
			status, err := e.nativeAttemptStatus(ctx, attempt)
			if err != nil {
				return spec.RunResult{}, err
			}
			if status == "complete" {
				if _, err := e.verifySeed(ctx, runID, op, v, beforeVerification); err != nil {
					return spec.RunResult{}, err
				}
			}
			var evidence any = map[string]string{"reconciled": "original native Job and bound receiver Pod terminated; complete files retained"}
			if gitOpsPhase(p) {
				worker, err := e.operationWorker(ctx, runID, op.ID, attempt.Attempt, op.ID)
				if err != nil {
					return spec.RunResult{}, err
				}
				step := spec.StepResult{ID: op.ID, Attempt: attempt.Attempt, Status: "fail", ExternalID: worker.Name, FinishedAt: spec.Now()}
				if status == "complete" {
					step.Status = "pass"
				}
				evidence = step
			}
			if err := e.Store.Complete(ctx, attempt, status, evidence); err != nil {
				return spec.RunResult{}, err
			}
			if gitOpsPhase(p) {
				if err := e.clusterRecord(ctx, runID, record.PlanDigest, status, evidence); err != nil {
					return spec.RunResult{}, err
				}
			}
			continue
		}
		worker, err := e.operationWorker(ctx, runID, attempt.StepID, attempt.Attempt, op.ID)
		if err != nil {
			return spec.RunResult{}, err
		}
		status, err := e.inspectWorker(ctx, worker)
		if err != nil {
			return spec.RunResult{}, err
		}
		if status == "complete" {
			if op.Type == "probe" {
				if _, err := e.probe(ctx, p, runID, op, v); err != nil {
					return spec.RunResult{}, err
				}
			}
			if op.Type == "seed" {
				if _, err := e.verifySeed(ctx, runID, op, v, beforeVerification); err != nil {
					return spec.RunResult{}, err
				}
			}
			if err := e.Store.Complete(ctx, attempt, "complete", map[string]string{"reconciled": "recorded terminal Job completion"}); err != nil {
				return spec.RunResult{}, err
			}
			continue
		}
		if status == "failed" {
			return spec.RunResult{}, spec.Err(14, "prior Job failed; select a supported recovery plan")
		}
		if status == "running" {
			return spec.RunResult{}, spec.Err(13, "prior Job is still running; no duplicate Job is started")
		}
		return spec.RunResult{}, spec.Err(13, "prior worker identity or termination cannot be established; application commit queries cannot fence an unobservable worker")
	}
	result := newResult(p, runID, record.PlanDigest)
	if len(record.Result) > 0 {
		if err := spec.Decode(record.Result, &result); err != nil {
			return result, err
		}
	}
	return e.execute(ctx, p, v, policy, a, approved, coord, result, false)
}
