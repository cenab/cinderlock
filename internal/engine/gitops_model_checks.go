package engine

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

// The two fixed verification points retain separate original worker identities.
type gitOpsModelIntent struct {
	Type           string                  `json:"type"`
	Phase          string                  `json:"phase"`
	Asset          string                  `json:"asset"`
	BindingDigest  string                  `json:"bindingDigest"`
	Preparation    spec.GitOpsRunReference `json:"preparation"`
	PlanDigest     string                  `json:"planDigest"`
	SnapshotDigest string                  `json:"snapshotDigest"`
}

func gitOpsModelStep(phase, asset string) string { return "@gitops-model/" + phase + "/" + asset }

func (e *Engine) gitOpsModelIntent(ctx context.Context, p spec.Plan, v *bundle.Verified, phase, asset string) (gitOpsModelIntent, spec.Operation, error) {
	var intent gitOpsModelIntent
	if !gitOpsApplicationChecks(p) || p.GitOps == nil || p.GitOps.Preparation == nil || phase != "start" && phase != "finish" {
		return intent, spec.Operation{}, spec.Err(13, "model verification is outside the exact GitOps check phase")
	}
	application, _, err := gitOpsSignedSeeds(v)
	if err != nil {
		return intent, spec.Operation{}, err
	}
	at := slices.IndexFunc(application, func(seed spec.Operation) bool { return seed.Asset == asset })
	if at < 0 {
		return intent, spec.Operation{}, spec.Err(13, "model verification has no selected signed application seed")
	}
	seed := application[at]
	binding, err := e.gitOpsPreparedVolume(ctx, p, v, seed.PVC)
	if err != nil {
		return intent, seed, err
	}
	digest, err := spec.Digest(binding)
	if err != nil {
		return intent, seed, err
	}
	planDigest, err := spec.Digest(p)
	if err != nil {
		return intent, seed, err
	}
	return gitOpsModelIntent{Type: "gitops-model-verification", Phase: phase, Asset: asset, BindingDigest: digest, Preparation: *p.GitOps.Preparation, PlanDigest: planDigest, SnapshotDigest: p.SnapshotDigest}, seed, nil
}

func (e *Engine) validateGitOpsModelIntent(ctx context.Context, p spec.Plan, v *bundle.Verified, record state.Operation) error {
	var actual gitOpsModelIntent
	if spec.Decode(record.Intent, &actual) != nil || record.StepID != gitOpsModelStep(actual.Phase, actual.Asset) {
		return spec.Err(13, "recorded GitOps model verification scope is malformed")
	}
	expected, _, err := e.gitOpsModelIntent(ctx, p, v, actual.Phase, actual.Asset)
	if err != nil {
		return err
	}
	a, aErr := spec.Digest(actual)
	b, bErr := spec.Digest(expected)
	if aErr != nil || bErr != nil || a != b {
		return spec.Err(13, "recorded GitOps model verification differs from current exact preparation and source bindings")
	}
	return nil
}

func (e *Engine) reconcileGitOpsModelVerification(ctx context.Context, p spec.Plan, v *bundle.Verified, record state.Operation) error {
	if err := e.validateGitOpsModelIntent(ctx, p, v, record); err != nil {
		return err
	}
	worker, err := e.operationWorker(ctx, record.RunID, record.StepID, record.Attempt, record.StepID)
	if err != nil {
		return err
	}
	if status, err := e.inspectWorker(ctx, worker); err != nil || status != "complete" {
		return spec.Err(13, "original read-only model verifier is not confirmed complete; no duplicate is started")
	}
	step := spec.StepResult{ID: record.StepID, Attempt: record.Attempt, Status: "pass", FinishedAt: spec.Now(), ExternalID: worker.Name}
	if err := e.Store.Complete(ctx, record, "complete", step); err != nil {
		return err
	}
	planDigest, err := spec.Digest(p)
	if err != nil {
		return err
	}
	return e.clusterRecord(ctx, record.RunID, planDigest, "complete", step)
}

func (e *Engine) verifyGitOpsModels(ctx context.Context, p spec.Plan, v *bundle.Verified, runID, phase string, boundary func() (spec.TargetSnapshot, error), result *spec.RunResult) error {
	application, _, err := gitOpsSignedSeeds(v)
	if err != nil {
		return err
	}
	for _, seed := range application {
		body, _, err := e.gitOpsModelIntent(ctx, p, v, phase, seed.Asset)
		if err != nil {
			return err
		}
		id := gitOpsModelStep(phase, seed.Asset)
		intent, previous := e.Store.LatestOperation(ctx, runID, id)
		if previous == nil {
			if err := e.validateGitOpsModelIntent(ctx, p, v, intent); err != nil {
				return err
			}
			if intent.State != "complete" {
				return spec.Err(13, "recorded model verification must be reconciled; no duplicate is started")
			}
			worker, err := e.operationWorker(ctx, runID, id, intent.Attempt, id)
			if err != nil {
				return err
			}
			if status, err := e.inspectWorker(ctx, worker); err != nil || status != "complete" {
				return spec.Err(13, "original model verification worker identity or completion changed")
			}
			var step spec.StepResult
			if spec.Decode(intent.Evidence, &step) != nil || step.ID != id || step.Attempt != intent.Attempt || step.Status != "pass" || step.ExternalID != worker.Name {
				return spec.Err(13, "model verification lacks its original completed receipt")
			}
			mergeGitOpsModelStep(result, step)
			continue
		}
		if !errors.Is(previous, sql.ErrNoRows) {
			return previous
		}
		binding, err := e.gitOpsPreparedVolume(ctx, p, v, seed.PVC)
		if err != nil {
			return err
		}
		image, err := e.image(v, e.Site.Spec.HelperImage)
		if err != nil {
			return err
		}
		if _, err := boundary(); err != nil {
			return err
		}
		intent, err = e.Store.Intent(ctx, runID, id, body, jobName(runID, id))
		if err != nil {
			return err
		}
		if err := e.clusterRecord(ctx, runID, body.PlanDigest, "intent", intent); err != nil {
			return err
		}
		args := []string{"--root", "/cinderlock-model", "--manifest", "/cinderlock-manifest/files.json"}
		if binding.SubPath != "" {
			args = append(args, "--subpath", binding.SubPath)
		}
		step := spec.StepResult{ID: id, Attempt: intent.Attempt, Status: "pass", StartedAt: spec.Now()}
		step.ExternalID, err = e.executeJobWithOptions(ctx, runID, id, image, []string{"/usr/local/bin/cinderlock", "helper", "verify-model"}, args, nil, seed.PVC, "/cinderlock-model", seed.TimeoutSeconds, &jobOptions{ReadOnlyPVC: true, ManifestConfigMap: binding.Manifest, IntentStepID: id, BeforeCreate: func() error {
			if _, err := boundary(); err != nil {
				return spec.Err(13, "model verifier did not start under current authority: %v", err)
			}
			return nil
		}})
		step.FinishedAt = spec.Now()
		state := "complete"
		if err != nil {
			state, step.Status, step.Error = "failed", "fail", err.Error()
			if spec.ExitCode(err) == 13 || ctx.Err() != nil {
				state, step.Status = "uncertain", "blocked"
			}
		}
		persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		recorded := e.Store.Complete(persist, intent, state, step)
		if recorded == nil {
			recorded = e.clusterRecord(persist, runID, body.PlanDigest, state, step)
		}
		cancel()
		mergeGitOpsModelStep(result, step)
		if recorded != nil {
			return spec.Err(13, "model verifier outcome could not be durably recorded")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func mergeGitOpsModelStep(result *spec.RunResult, step spec.StepResult) {
	if at := slices.IndexFunc(result.Steps, func(prior spec.StepResult) bool { return prior.ID == step.ID }); at >= 0 {
		result.Steps[at] = step
	} else {
		result.Steps = append(result.Steps, step)
	}
}
