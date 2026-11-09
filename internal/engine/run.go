package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (e *Engine) Apply(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy, a *spec.Authorization, approved bool) (spec.RunResult, error) {
	if e.Store == nil {
		return spec.RunResult{}, errors.New("durable run store is required")
	}
	if err := e.checkPlan(ctx, p, v, policy, true); err != nil {
		return spec.RunResult{}, err
	}
	nonce, err := e.authorize(p, policy, a, approved)
	if err != nil {
		return spec.RunResult{}, err
	}
	if p.Kind != "Plan" && p.Kind != "RecoveryPlan" && p.Kind != "ProbePlan" && p.Kind != "RetirementPlan" && p.Kind != "ArtifactsPlan" && !gitOpsPhase(p) {
		return spec.RunResult{}, spec.Err(2, "unsupported plan kind")
	}
	if gitOpsPhase(p) {
		if _, err := e.gitOpsStageReference(ctx, p.GitOps.Staging, v, p.SitePath, policy, true); err != nil {
			return spec.RunResult{}, err
		}
	}
	if p.Kind == "RecoveryPlan" {
		if p.SourceRun == "" {
			return spec.RunResult{}, spec.Err(2, "recovery plan must bind a source run")
		}
		if err := e.recoveryQuiescent(ctx, p.SourceRun); err != nil {
			return spec.RunResult{}, err
		}
	}
	if p.SourceRun != "" {
		if err := e.verifyHandoffAdmission(ctx, p); err != nil {
			return spec.RunResult{}, err
		}
	}
	runID := randomID()
	digest, err := spec.Digest(p)
	if err != nil {
		return spec.RunResult{}, err
	}
	coord, err := e.acquire(ctx, runID, p.SourceRun)
	if err != nil {
		return spec.RunResult{}, err
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = coord.release(release)
	}()
	planJSON, err := spec.Canonical(p)
	if err != nil {
		return spec.RunResult{}, err
	}
	siteJSON, err := spec.Canonical(e.Site)
	if err != nil {
		return spec.RunResult{}, err
	}
	record := state.Run{ID: runID, Application: p.Metadata.Application, Namespace: e.Site.Spec.Namespace, TargetID: p.Snapshot.TargetID, PlanDigest: digest, BundleDigest: p.BundleDigest, State: "acquiring", Plan: planJSON, Site: siteJSON}
	if p.SourceRun != "" {
		if err := e.verifyHandoffAdmission(ctx, p); err != nil {
			return spec.RunResult{}, err
		}
	}
	if err := e.Store.AdmitRun(ctx, record, p.SourceRun, &state.Authorization{Nonce: nonce, PolicyDigest: p.PolicyDigest, ExpiresAt: authorizationExpiry(a)}); err != nil {
		if errors.Is(err, state.ErrAuthorizationUsed) {
			return spec.RunResult{}, spec.Err(16, "execution authorization nonce already belongs to another run")
		}
		if errors.Is(err, state.ErrActiveRun) {
			return spec.RunResult{}, spec.Err(18, "an unresolved application run blocks new execution: %v", err)
		}
		return spec.RunResult{}, err
	}
	result := newResult(p, runID, digest)
	record.Active = true
	if p.SourceRun != "" {
		err = e.completeHandoff(ctx, record, p)
	} else {
		err = e.clusterRecord(ctx, runID, digest, "acquiring", nil)
	}
	if err != nil {
		_ = e.Store.SetState(context.Background(), runID, "blocked", true, result)
		return result, err
	}

	return e.execute(ctx, p, v, policy, a, approved, coord, result, true)
}

func newResult(p spec.Plan, id, digest string) spec.RunResult {
	r := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: id, PlanDigest: digest, BundleDigest: p.BundleDigest, SiteID: p.Snapshot.SiteID, TargetID: p.Snapshot.TargetID, State: "acquiring", Acceptance: "not_established", StartedAt: spec.Now(), Steps: []spec.StepResult{}, Checks: []spec.CheckResult{}, Domains: map[string]string{"integrity": "pass", "readiness": "not_tested", "workflow": "not_tested", "recovery": "not_tested"}, Findings: []spec.Finding{}, RecoveryCoverage: "not tested on this target; no production recovery claim", OfflineCoverage: "customer network enforcement; Cinderlock did not establish isolation", SourceRun: p.SourceRun}
	r.Metadata = p.Metadata
	return r
}

func (e *Engine) execute(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy, a *spec.Authorization, approved bool, coord *coordinator, result spec.RunResult, firstExecution bool) (spec.RunResult, error) {
	if result.Error != "" || result.FinishedAt != "" {
		if err := e.Store.Event(ctx, result.RunID, "run_resumed", map[string]any{"previousOutcome": result}); err != nil {
			return result, spec.Err(13, "previous run outcome could not be retained before resume")
		}
	}
	result.State = "mutating"
	result.Error, result.FinishedAt = "", ""
	fail := func(err error) (spec.RunResult, error) {
		if ctx.Err() != nil && spec.ExitCode(err) != 17 {
			err = spec.Err(13, "local execution wait ended; reconcile the original recorded worker outcomes before continuing")
		}
		result.Error = err.Error()
		result.FinishedAt = spec.Now()
		result.State = "failed"
		if spec.ExitCode(err) == 13 || spec.ExitCode(err) == 18 {
			result.State = "needs_reconciliation"
		}
		if spec.ExitCode(err) == 17 {
			result.State = "stopped"
		}
		if p.Kind == "RecoveryPlan" && result.State == "failed" {
			result.State = "recovery_failed"
		}
		active := true
		if p.Kind == "ProbePlan" && result.State != "needs_reconciliation" {
			result.State = "probe_failed"
			active = false
		}
		if p.Kind == "ArtifactsPlan" && result.State != "needs_reconciliation" {
			result.State, active = "artifacts_failed", false
		}
		if p.Kind == "GitOpsPreparePlan" && result.State != "needs_reconciliation" {
			result.State, active = "gitops_prepare_failed", false
		}
		persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if recordErr := e.Store.SetState(persist, result.RunID, result.State, active, result); recordErr != nil {
			return result, fmt.Errorf("%w; result persistence also failed: %v", err, recordErr)
		}
		if recordErr := e.clusterRecord(persist, result.RunID, result.PlanDigest, result.State, nil); recordErr != nil {
			return result, fmt.Errorf("%w; cluster result persistence also failed: %v", err, recordErr)
		}
		return result, err
	}
	// Fresh admission cannot have started an operation; resume has no such guarantee.
	if firstExecution && ctx.Err() != nil {
		return fail(spec.Err(17, "stop requested before first operation"))
	}
	checkBoundary := func() (spec.TargetSnapshot, error) {
		return e.executionBoundary(ctx, result.RunID, p, v, policy, a, approved, coord)
	}
	hasPrerequisites := len(prerequisiteCheckIDs(p, v)) != 0
	ops, err := e.Store.Operations(ctx, result.RunID)
	if err != nil {
		return fail(err)
	}
	retainedOptionalFailures := map[string]bool{}
	for _, check := range p.Checks {
		if check.ObservationContract == nil {
			continue
		}
		check.Required = check.Required || slices.Contains(p.RequiredChecks, check.ID)
		for _, record := range ops {
			if record.StepID != checkStepID(check.ID) || (record.State != "complete" && record.State != "failed") {
				continue
			}
			if err := checkIntentMatches(record.Intent, check); err != nil {
				return fail(err)
			}
			r := e.recordedObservationCheck(ctx, record, check, spec.CheckResult{ID: check.ID, Domain: check.Domain, Required: check.Required, Status: "blocked"})
			mergeCheckResults(&result, []spec.CheckResult{r})
			if record.State == "failed" && !check.Required && r.Status == "fail" && r.Observations != nil && r.Observations.Report != nil {
				worker, err := e.operationWorker(ctx, record.RunID, record.StepID, record.Attempt, record.StepID)
				if err == nil {
					_, err = e.observationPod(ctx, worker, &r.Observations.Source)
				}
				if err != nil {
					return fail(err)
				}
				retainedOptionalFailures[record.StepID] = true
			}
			if r.Required && r.Status != "pass" && result.Domains["workflow"] != "fail" {
				result.Domains["workflow"] = r.Status
			}
		}
	}
	completed := e.gitOpsCoveredSteps(p, v)
	for _, record := range ops {
		if journalKind(record.Intent) == "gitops-model-verification" {
			if err := e.validateGitOpsModelIntent(ctx, p, v, record); err != nil {
				return fail(err)
			}
			continue
		}
		if record.State == "complete" {
			completed[record.StepID] = true
			if (p.Kind == "ArtifactsPlan" || gitOpsPhase(p)) && journalKind(record.Intent) != "check" {
				var step spec.StepResult
				if err := spec.Decode(record.Evidence, &step); err != nil {
					return fail(err)
				}
				at := slices.IndexFunc(result.Steps, func(previous spec.StepResult) bool { return previous.ID == step.ID && previous.Attempt == step.Attempt })
				if at >= 0 {
					result.Steps[at] = step
				} else {
					result.Steps = append(result.Steps, step)
				}
			}
		} else if record.State == "failed" {
			if journalKind(record.Intent) == "check" {
				if retainedOptionalFailures[record.StepID] {
					continue
				}
				return fail(spec.Err(15, "a recorded acceptance worker failed; use a supported recovery plan"))
			}
			var operation spec.Operation
			if err := spec.Decode(record.Intent, &operation); err != nil {
				return fail(err)
			}
			if (isJob(operation.Type) || operation.Type == "seed" && len(operation.Command) != 0) && !operation.Idempotent {
				return fail(spec.Err(13, "failed non-idempotent operation %s may have partial effects; use declared reconciliation/recovery instead of repeating it", record.StepID))
			}
			if operation.Type == "seed" && len(operation.Command) == 0 {
				if _, err := e.nativeAttemptStatus(ctx, record); err != nil {
					return fail(err)
				}
			}
		} else if record.State == "intent" || record.State == "uncertain" {
			return fail(spec.Err(13, "operation %s has an uncertain outcome; reconcile before continuing", record.StepID))
		}
	}
	for _, o := range p.Operations {
		if completed[o.ID] {
			continue
		}
		if ctx.Err() != nil {
			return fail(spec.Err(17, "stop requested before next operation"))
		}
		for _, dep := range o.DependsOn {
			if !completed[dep] {
				return fail(spec.Err(10, "operation dependency not completed: %s", dep))
			}
		}
		if !slices.Contains(e.Site.Spec.AllowedActions, o.Type) || !slices.Contains(policy.Spec.AllowedActions, o.Type) {
			return fail(spec.Err(16, "operation capability no longer permitted"))
		}
		var before spec.TargetSnapshot
		if o.Type != "import" && hasPrerequisites {
			checks, err := e.prerequisiteChecks(ctx, p, v, result.RunID, checkBoundary)
			if err != nil {
				recordPrerequisiteFailure(&result, checks)
				return fail(err)
			}
			mergeCheckResults(&result, checks)
		}
		before, err = checkBoundary()
		if err != nil {
			return fail(err)
		}
		external := ""
		if jobOperation(o.Type) && !(o.Type == "seed" && len(o.Command) == 0) {
			external = jobName(result.RunID, o.ID)
		}
		intent, err := e.Store.Intent(ctx, result.RunID, o.ID, o, external)
		if err != nil {
			return fail(err)
		}
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, "intent", intent); err != nil {
			return fail(err)
		}
		step := spec.StepResult{ID: o.ID, Attempt: intent.Attempt, Status: "running", StartedAt: spec.Now(), ExternalID: external}
		external, err = e.operation(ctx, p, result.RunID, o, v, policy, func() error { _, err := checkBoundary(); return err })
		if err == nil {
			_, err = e.advanceCheckpoint(ctx, result.RunID, p, v, policy, o, before)
		}
		step.ExternalID = external
		step.FinishedAt = spec.Now()
		status := "complete"
		step.Status = "pass"
		if err != nil {
			status = "failed"
			step.Status = "fail"
			step.Error = err.Error()
			if spec.ExitCode(err) == 13 || spec.ExitCode(err) == 18 || ctx.Err() != nil {
				status = "uncertain"
				step.Status = "blocked"
			}
		}
		persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		recordErr := e.Store.Complete(persist, intent, status, step)
		if recordErr == nil {
			recordErr = e.clusterRecord(persist, result.RunID, result.PlanDigest, status, step)
		}
		cancel()
		result.Steps = append(result.Steps, step)
		if o.Type == "probe" && err == nil {
			result.Steps[len(result.Steps)-1].Evidence = e.hardwarePath(result.RunID)
		}
		if recordErr != nil {
			return fail(spec.Err(13, "external operation ran but durable outcome was not recorded: %v", recordErr))
		}
		if err != nil {
			return fail(err)
		}
		completed[o.ID] = true
		if err := e.Store.SetState(ctx, result.RunID, "mutating", true, result); err != nil {
			return fail(err)
		}
	}
	if err := coord.check(ctx); err != nil {
		return fail(err)
	}
	if err := e.checkPlan(ctx, p, v, policy, false); err != nil {
		return fail(err)
	}
	if _, err := e.authorize(p, policy, a, approved); err != nil {
		return fail(err)
	}
	if p.Kind == "ArtifactsPlan" {
		result.State, result.FinishedAt = "artifacts_staged", spec.Now()
		result.Findings = append(result.Findings, p.Findings...)
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, result.State, result); err != nil {
			return fail(err)
		}
		if err := e.Store.SetState(ctx, result.RunID, result.State, false, result); err != nil {
			return fail(err)
		}
		return result, nil
	}
	if p.Kind == "GitOpsPreparePlan" {
		if err := e.gitOpsPreparationComplete(ctx, p, v, result.RunID); err != nil {
			return fail(err)
		}
		if _, err := checkBoundary(); err != nil {
			return fail(err)
		}
		result.State, result.FinishedAt = "gitops_prepared", spec.Now()
		result.Findings = append(result.Findings, p.Findings...)
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, result.State, result); err != nil {
			return fail(err)
		}
		if err := e.Store.SetState(ctx, result.RunID, result.State, false, result); err != nil {
			return fail(err)
		}
		return result, nil
	}
	if p.Kind == "RetirementPlan" {
		if err := e.verifyRetained(ctx, p.RetainedResources); err != nil {
			return fail(err)
		}
		result.State = "retired"
		result.Acceptance = "not_applicable"
		result.Domains["readiness"] = "pass"
		result.FinishedAt = spec.Now()
		result.Findings = append(result.Findings, p.Findings...)
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, result.State, result); err != nil {
			return fail(err)
		}
		if err := e.Store.SetState(ctx, result.RunID, result.State, false, result); err != nil {
			return fail(err)
		}
		return result, nil
	}
	if p.Kind == "ProbePlan" {
		result.State = "probe_complete"
		result.FinishedAt = spec.Now()
		result.Domains["readiness"] = "pass"
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, result.State, result); err != nil {
			return fail(err)
		}
		if err := e.Store.SetState(ctx, result.RunID, result.State, false, result); err != nil {
			return fail(err)
		}
		return result, nil
	}
	result.State = "verifying"
	if err := e.Store.SetState(ctx, result.RunID, result.State, true, result); err != nil {
		return fail(err)
	}
	final, err := e.inspectPlan(ctx, p, v, policy)
	if err != nil {
		return fail(err)
	}
	if err := targetObservationError(final); err != nil {
		result.Domains["readiness"] = "blocked"
		return fail(err)
	}
	ready := true
	for _, fact := range final.Facts {
		if strings.HasPrefix(fact.Name, "readiness/") && fact.Value != "true" {
			ready = false
		}
	}
	if !ready {
		result.Domains["readiness"] = "fail"
		return fail(spec.Err(14, "post-change workloads are not ready"))
	}
	result.Domains["readiness"] = "pass"
	if !gitOpsPhase(p) {
		if err := e.verifyGPUAssignment(ctx, v); err != nil {
			result.Domains["readiness"] = "blocked"
			return fail(err)
		}
	}
	if p.Kind == "GitOpsChecksPlan" {
		if checks, err := e.prerequisiteChecks(ctx, p, v, result.RunID, checkBoundary); err != nil {
			recordPrerequisiteFailure(&result, checks)
			return fail(err)
		} else {
			mergeCheckResults(&result, checks)
		}
		if err := e.verifyGitOpsModels(ctx, p, v, result.RunID, "start", checkBoundary, &result); err != nil {
			return fail(err)
		}
	}
	required := map[string]bool{}
	for _, id := range p.RequiredChecks {
		required[id] = true
	}
	for _, check := range p.Checks {
		check.Required = check.Required || required[check.ID]
		if !slices.Contains(e.Site.Spec.AllowedActions, "job") || !slices.Contains(policy.Spec.AllowedActions, "job") {
			r := spec.CheckResult{ID: check.ID, Domain: check.Domain, Required: check.Required, Status: "blocked", Reason: "acceptance Job capability not authorized"}
			mergeCheckResults(&result, []spec.CheckResult{r})
			continue
		}
		if hasPrerequisites {
			if checks, err := e.prerequisiteChecks(ctx, p, v, result.RunID, checkBoundary); err != nil {
				recordPrerequisiteFailure(&result, checks)
				return fail(err)
			}
		}
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, "verifying", check); err != nil {
			return fail(err)
		}
		var boundaryErr error
		r := e.check(ctx, result.RunID, check, v, func() (spec.TargetSnapshot, error) {
			var snapshot spec.TargetSnapshot
			snapshot, boundaryErr = checkBoundary()
			return snapshot, boundaryErr
		})
		if boundaryErr != nil {
			if r.Evidence != "" {
				mergeCheckResults(&result, []spec.CheckResult{r})
			}
			return fail(boundaryErr)
		}
		mergeCheckResults(&result, []spec.CheckResult{r})
		if r.Status == "blocked" {
			attempt, err := e.Store.LatestOperation(ctx, result.RunID, checkStepID(check.ID))
			if err == nil && (attempt.State == "intent" || attempt.State == "uncertain") {
				return fail(spec.Err(13, "acceptance worker outcome is uncertain; establish termination before recovery"))
			}
		}
	}
	passed := map[string]bool{}
	for _, check := range result.Checks {
		if check.Status == "pass" {
			passed[check.ID] = true
		}
		if check.Required && check.Status != "pass" {
			result.Domains["workflow"] = check.Status
			return fail(spec.Err(15, "required workflow %s did not pass: %s", check.ID, check.Reason))
		}
	}
	for id := range required {
		if !passed[id] {
			result.Domains["workflow"] = "blocked"
			return fail(spec.Err(15, "required workflow %s has no passing result", id))
		}
	}
	result.Domains["workflow"] = "pass"
	if checks, err := e.prerequisiteChecks(ctx, p, v, result.RunID, checkBoundary); err != nil {
		recordPrerequisiteFailure(&result, checks)
		return fail(err)
	}
	if p.Kind == "GitOpsChecksPlan" {
		if err := e.verifyGitOpsModels(ctx, p, v, result.RunID, "finish", checkBoundary, &result); err != nil {
			return fail(err)
		}
		result.Findings = append(result.Findings, p.Findings...)
	}
	if _, err := checkBoundary(); err != nil {
		return fail(err)
	}
	result.State = "succeeded"
	result.Acceptance = "pass"
	result.FinishedAt = spec.Now()
	if p.Kind == "RecoveryPlan" {
		result.State = "recovered"
		result.Domains["recovery"] = "pass"
		result.RecoveryCoverage = "executed declared recovery on this target; data scope is the recovery plan"
	}
	if err := e.Store.AcceptRelease(ctx, result.TargetID, p.Metadata.Application, p.Metadata.Channel, p.Metadata.Sequence, p.BundleDigest); err != nil {
		return fail(err)
	}
	if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, result.State, result); err != nil {
		return fail(err)
	}
	if err := e.Store.SetState(ctx, result.RunID, result.State, false, result); err != nil {
		return fail(err)
	}
	return result, nil
}

func isJob(kind string) bool {
	return kind == "job" || kind == "migrate" || kind == "backup" || kind == "reindex"
}

func jobOperation(kind string) bool { return isJob(kind) || kind == "seed" || kind == "probe" }

func (e *Engine) operation(ctx context.Context, p spec.Plan, runID string, o spec.Operation, v *bundle.Verified, policy spec.TrustPolicy, beforeVerification func() error) (string, error) {
	if isJob(o.Type) {
		if err := spec.ValidateOperation(o); err != nil {
			return "", err
		}
		image, err := e.image(v, o.Image)
		if err != nil {
			return "", err
		}
		if o.ExpectedExitCode != 0 {
			return "", spec.Err(10, "nonzero expected exits require a qualified result adapter")
		}
		return e.executeJobWithOptions(ctx, runID, o.ID, image, o.Command, o.Args, o.SecretRefs, o.PVC, o.MountPath, o.TimeoutSeconds, &jobOptions{Resources: o.Script.Resources})
	}
	switch o.Type {
	case "uninstall":
		return "helm/" + e.Site.Spec.ReleaseName, e.uninstall(ctx, p)
	case "probe":
		return e.probe(ctx, p, runID, o, v)
	case "import":
		if e.Site.Spec.Registry == "" {
			return "", spec.Err(10, "internal registry required")
		}
		if e.Site.Spec.RegistryPlainHTTP && (!slices.Contains(e.Site.Spec.AllowedActions, "registry-http") || !slices.Contains(policy.Spec.AllowedActions, "registry-http")) {
			return "", spec.Err(16, "plain HTTP registry requires site and policy capability registry-http")
		}
		options, err := e.registryOptions(ctx)
		if err != nil {
			return "", err
		}
		targets, err := importTargets(v, o.Asset)
		if err != nil {
			return "", err
		}
		imported := ""
		for _, asset := range targets {
			destination := strings.TrimSuffix(e.Site.Spec.Registry, "/") + "/" + strings.ToLower(asset.ID)
			var err error
			if imported, err = bundle.ImportImage(ctx, v, asset.ID, destination, options); err != nil {
				return destination, spec.Err(13, "image import outcome requires digest reconciliation: %v", err)
			}
		}
		if p.Kind == "ArtifactsPlan" {
			return imported, nil
		}
		return e.Site.Spec.Registry, nil
	case "helm":
		if p.Kind == "RecoveryPlan" && p.TargetVersion != v.Index.Lock.Release.Metadata.Version {
			return "", spec.Err(10, "a Helm downgrade needs a separately packaged prior chart/values adapter; the target chart cannot be misrepresented as the prior release")
		}
		err := e.deploy(ctx, p, v)
		if err != nil {
			if spec.ExitCode(err) == 10 || spec.ExitCode(err) == 12 || spec.ExitCode(err) == 16 {
				return "", err
			}
			return "helm/" + e.Site.Spec.ReleaseName, spec.Err(13, "Helm exited before complete target outcome was established: %v", err)
		}
		return "helm/" + e.Site.Spec.ReleaseName, nil
	case "restart":
		if o.Service == "" {
			return "", spec.Err(2, "restart needs a named Deployment")
		}
		d, err := e.Kube.Client.AppsV1().Deployments(e.Site.Spec.Namespace).Get(ctx, o.Service, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		if err := checkOwner(&d.ObjectMeta, e.Site.Spec.ReleaseName, nil); err != nil {
			return "", err
		}
		if d.Labels["app.kubernetes.io/instance"] != e.Site.Spec.ReleaseName {
			return "", spec.Err(16, "restart Deployment is outside the managed release")
		}
		_, err = e.Kube.Client.AppsV1().Deployments(e.Site.Spec.Namespace).Update(ctx, RestartSpec(d, runID), metav1.UpdateOptions{})
		if err != nil {
			return "deployment/" + o.Service, spec.Err(13, "restart update outcome requires reconciliation: %v", err)
		}
		return "deployment/" + o.Service, e.waitDeployment(ctx, o.Service, o.TimeoutSeconds, runID, string(d.UID))
	case "seed":
		return e.seedPVC(ctx, runID, o, v, beforeVerification)
	case "gitops":
		return "", spec.Err(10, "GitOps owns this release; export and review the source change instead of direct mutation")
	default:
		return "", spec.Err(10, "unsupported operation type %s", o.Type)
	}
}
