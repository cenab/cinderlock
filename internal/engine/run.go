package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

func (e *Engine) authorize(p spec.Plan, policy spec.TrustPolicy, a *spec.Authorization, approved bool) (string, error) {
	digest, err := spec.Digest(p)
	if err != nil {
		return "", err
	}
	if a == nil {
		if policy.Spec.RequireAuthorization || !policy.Spec.AllowInteractive || !approved {
			return "", spec.Err(16, "this exact plan requires site-authorized execution approval")
		}
		return "interactive:" + digest, nil
	}
	if err := spec.ValidateHeader(a.Header, "Authorization"); err != nil {
		return "", err
	}
	if a.PlanDigest != digest || a.PlanKind != p.Kind || a.TargetID != p.Snapshot.TargetID || a.PolicyDigest != p.PolicyDigest || a.PolicyEpoch != policy.Spec.Epoch || a.Nonce == "" {
		return "", spec.Err(16, "authorization does not bind the current plan, target and policy")
	}
	expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return "", spec.Err(16, "authorization expired or invalid")
	}
	for _, capability := range spec.PlanActions(p) {
		if !slices.Contains(a.Actions, capability) {
			return "", spec.Err(16, "authorization does not cover action %s", capability)
		}
	}
	body, err := spec.AuthorizationBytes(*a)
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature.Signature)
	if err != nil || a.Signature.Algorithm != "Ed25519" {
		return "", spec.Err(16, "invalid execution authorization signature")
	}
	valid := false
	for _, key := range policy.Spec.Keys {
		if key.ID != a.Signature.KeyID || key.Revoked || !slices.Contains(key.Roles, "approval") || !matches(key.Applications, p.Metadata.Application) || !matches(key.Channels, p.Metadata.Channel) {
			continue
		}
		public, err := bundle.ParsePublicKey(key.PublicKey)
		if err != nil {
			return "", err
		}
		if ed25519.Verify(public, append([]byte(spec.AuthorizationDomain+"\x00"), body...), sig) {
			valid = true
		}
	}
	if !valid {
		return "", spec.Err(16, "authorization signer lacks independently admitted approval authority")
	}
	return a.Nonce, nil
}

func matches(values []string, value string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, value)
}

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
	if p.Kind != "Plan" && p.Kind != "RecoveryPlan" && p.Kind != "ProbePlan" && p.Kind != "RetirementPlan" && p.Kind != "ArtifactsPlan" {
		return spec.RunResult{}, spec.Err(2, "unsupported plan kind")
	}
	if p.Kind == "RecoveryPlan" {
		if p.SourceRun == "" {
			return spec.RunResult{}, spec.Err(2, "recovery plan must bind a source run")
		}
		if err := e.recoveryQuiescent(ctx, p.SourceRun); err != nil {
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
	if err := e.clusterRecord(ctx, runID, digest, "acquiring", nil); err != nil {
		_ = e.Store.SetState(context.Background(), runID, "blocked", true, result)
		return result, err
	}
	if p.SourceRun != "" {
		source, err := e.Store.Run(ctx, p.SourceRun)
		if err != nil {
			return result, err
		}
		if err := e.clusterRecord(ctx, p.SourceRun, source.PlanDigest, "superseded", map[string]string{"recoveryRun": runID}); err != nil {
			return result, err
		}
	}
	return e.execute(ctx, p, v, policy, a, approved, coord, result, true)
}

func authorizationExpiry(a *spec.Authorization) string {
	if a == nil {
		return "interactive"
	}
	return a.ExpiresAt
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
		if err := coord.check(ctx); err != nil {
			return spec.TargetSnapshot{}, err
		}
		if err := e.checkPlan(ctx, p, v, policy, false); err != nil {
			return spec.TargetSnapshot{}, err
		}
		snapshot, err := e.currentCheckpoint(ctx, result.RunID, p)
		if err != nil {
			return spec.TargetSnapshot{}, err
		}
		_, err = e.authorize(p, policy, a, approved)
		return snapshot, err
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
	completed := map[string]bool{}
	for _, record := range ops {
		if record.State == "complete" {
			completed[record.StepID] = true
			if p.Kind == "ArtifactsPlan" {
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
		before, err := checkBoundary()
		if err != nil {
			return fail(err)
		}
		for _, dep := range o.DependsOn {
			if !completed[dep] {
				return fail(spec.Err(10, "operation dependency not completed: %s", dep))
			}
		}
		if !slices.Contains(e.Site.Spec.AllowedActions, o.Type) || !slices.Contains(policy.Spec.AllowedActions, o.Type) {
			return fail(spec.Err(16, "operation capability no longer permitted"))
		}
		if o.Type != "import" && hasPrerequisites {
			checks, err := e.prerequisiteChecks(ctx, p, v, result.RunID, checkBoundary)
			if err != nil {
				recordPrerequisiteFailure(&result, checks)
				return fail(err)
			}
			mergeCheckResults(&result, checks)
			before, err = checkBoundary()
			if err != nil {
				return fail(err)
			}
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
		external, err = e.operation(ctx, p, result.RunID, o, v, policy)
		if err == nil {
			_, err = e.advanceCheckpoint(ctx, result.RunID, p, o, before)
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
	final, err := e.Inspect(ctx)
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
	if err := e.verifyGPUAssignment(ctx, v); err != nil {
		result.Domains["readiness"] = "blocked"
		return fail(err)
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
		if _, err := checkBoundary(); err != nil {
			return fail(err)
		}
		if hasPrerequisites {
			if checks, err := e.prerequisiteChecks(ctx, p, v, result.RunID, checkBoundary); err != nil {
				recordPrerequisiteFailure(&result, checks)
				return fail(err)
			}
			if _, err := checkBoundary(); err != nil {
				return fail(err)
			}
		}
		if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, "verifying", check); err != nil {
			return fail(err)
		}
		r := e.check(ctx, result.RunID, check, v)
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
	if err := e.checkPlan(ctx, p, v, policy, false); err != nil {
		return fail(err)
	}
	if _, err := e.authorize(p, policy, a, approved); err != nil {
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

func (e *Engine) operation(ctx context.Context, p spec.Plan, runID string, o spec.Operation, v *bundle.Verified, policy spec.TrustPolicy) (string, error) {
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
		return e.seedPVC(ctx, runID, o, v)
	case "gitops":
		return "", spec.Err(10, "GitOps owns this release; export and review the source change instead of direct mutation")
	default:
		return "", spec.Err(10, "unsupported operation type %s", o.Type)
	}
}

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
	if err := e.verifyClusterRecord(ctx, runID, record.PlanDigest); err != nil {
		return spec.RunResult{}, err
	}
	coord, err := e.acquire(ctx, runID)
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
			before, err := e.currentCheckpoint(ctx, runID, p)
			if err != nil {
				return spec.RunResult{}, err
			}
			if err = e.checkPlan(ctx, p, v, policy, false); err != nil {
				return spec.RunResult{}, err
			}
			if _, err = e.authorize(p, policy, a, approved); err != nil {
				return spec.RunResult{}, err
			}
			external, err := e.operation(ctx, p, runID, op, v, policy)
			if err != nil {
				return spec.RunResult{}, err
			}
			if _, err = e.advanceCheckpoint(ctx, runID, p, op, before); err != nil {
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
				if _, err := e.verifySeed(ctx, runID, op, v); err != nil {
					return spec.RunResult{}, err
				}
			}
			if err := e.Store.Complete(ctx, attempt, status, map[string]string{"reconciled": "original native Job and bound receiver Pod terminated; complete files retained"}); err != nil {
				return spec.RunResult{}, err
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
				if _, err := e.verifySeed(ctx, runID, op, v); err != nil {
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

func (e *Engine) RecoveryPlan(ctx context.Context, runID, recoveryID, bundlePath, sitePath string, policy spec.TrustPolicy) (spec.Plan, error) {
	record, err := e.Store.Run(ctx, runID)
	if err != nil {
		return spec.Plan{}, err
	}
	var original spec.Plan
	if err := spec.Decode(record.Plan, &original); err != nil {
		return spec.Plan{}, err
	}
	var selected *spec.Recovery
	for i := range original.Recovery {
		r := &original.Recovery[i]
		if r.ID == recoveryID {
			selected = r
		}
	}
	if selected == nil {
		return spec.Plan{}, spec.Err(10, "no declared recovery procedure matches requested identity")
	}
	if !record.Active {
		return spec.Plan{}, spec.Err(10, "source run is terminal; recovery requires an explicit new supported transition")
	}
	verified, err := bundle.Verify(ctx, bundlePath, policy)
	if err != nil {
		return spec.Plan{}, err
	}
	defer verified.Close()
	if verified.Digest != original.BundleDigest {
		return spec.Plan{}, spec.Err(12, "recovery bundle differs from source run's signed bundle")
	}
	snapshot, err := e.Inspect(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	if snapshot.TargetID != record.TargetID || snapshot.NamespaceUID != original.Snapshot.NamespaceUID {
		return spec.Plan{}, spec.Err(11, "recovery target differs from original run")
	}
	p := original
	p.Header.Kind = "RecoveryPlan"
	p.SourceRun = runID
	p.Snapshot = snapshot
	p.SourceVersion = snapshot.InstalledVersion
	p.TargetVersion = selected.ToRelease
	p.Operations = selected.Operations
	p.Checks = selected.Checks
	p.RequiredChecks = nil
	p.Destructive = selected.Destructive
	p.CreatedAt = spec.Now()
	p.Findings = []spec.Finding{}
	p.Executable = true
	p.BundlePath = bundlePath
	p.SitePath = sitePath
	p.SourceSiteDigest, err = sourceSiteDigest(sitePath)
	if err != nil {
		return p, err
	}
	p.SnapshotDigest, err = snapshotDigest(snapshot)
	if err != nil {
		return p, err
	}
	p.SiteDigest, err = spec.Digest(e.Site)
	if err != nil {
		return p, err
	}
	p.PolicyDigest, err = spec.Digest(policy)
	if err != nil {
		return p, err
	}
	p.PolicyEpoch = policy.Spec.Epoch
	e.addPolicyFloorFindings(ctx, &p)
	for _, c := range selected.Checks {
		if c.Required {
			p.RequiredChecks = append(p.RequiredChecks, c.ID)
		}
	}
	if len(p.RequiredChecks) == 0 {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_ACCEPTANCE_MISSING", Severity: "blocker", Message: "recovery procedure has no required application acceptance checks"})
	}
	if len(p.Operations) == 0 {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_MANUAL_ONLY", Severity: "blocker", Message: "manual-only recovery has no executable operations"})
	}
	if selected.RequiresBackup && e.Site.Spec.BackupRef == "" {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "BACKUP_MISSING", Severity: "blocker", Message: "declared recovery requires a customer-approved backup reference"})
	}
	if selected.DataRevision != "" && selected.DataRevision != e.Site.Spec.DataRevision {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_DATA_MISMATCH", Severity: "blocker", Message: "data revision does not match recovery procedure"})
	}
	var objects []map[string]any
	e.addExecutionFindings(ctx, &p, verified, policy)
	e.addStorageFindings(ctx, &p, verified, policy)
	e.addConfigurationFindings(ctx, &p, verified)
	for _, operation := range p.Operations {
		if operation.Type != "helm" {
			continue
		}
		if p.TargetVersion != verified.Index.Lock.Release.Metadata.Version {
			p.Executable = false
			p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_CHART_UNAVAILABLE", Severity: "blocker", Message: "prior-release Helm recovery requires its separately packaged chart adapter"})
			break
		}
		objects, err = e.render(ctx, verified)
		if err != nil {
			return p, err
		}
		p.DesiredStateDigest, err = spec.Digest(objects)
		if err != nil {
			return p, err
		}
		break
	}
	e.addPermissionFindings(ctx, &p, objects)
	e.addAdmissionFindings(ctx, &p, objects, policy)
	if err := e.recoveryQuiescent(ctx, runID); err != nil {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_WORKER_UNRESOLVED", Severity: "blocker", Message: err.Error()})
	}
	return p, nil
}

func (e *Engine) recoveryQuiescent(ctx context.Context, runID string) error {
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
		if attempt.State == "complete" {
			continue
		}
		kind := journalKind(attempt.Intent)
		if kind == "seed" {
			var op spec.Operation
			if err := spec.Decode(attempt.Intent, &op); err != nil {
				return err
			}
			if len(op.Command) == 0 {
				if _, err := e.nativeAttemptStatus(ctx, attempt); err != nil {
					return err
				}
				continue
			}
		}
		if !jobOperation(kind) && kind != "check" {
			if attempt.State == "intent" || attempt.State == "uncertain" {
				return spec.Err(13, "uncertain %s must be reconciled before a recovery mutation", kind)
			}
			continue
		}
		found := false
		for _, worker := range workers {
			if worker.StepID != attempt.StepID || worker.Attempt != attempt.Attempt {
				continue
			}
			if worker.Role == attempt.StepID {
				found = true
			}
			status, err := e.inspectWorker(ctx, worker)
			if err != nil {
				return err
			}
			if status != "complete" && status != "failed" {
				return spec.Err(13, "prior Job is running or unobservable; recovery cannot race it")
			}
			if err := e.nativeWorkerQuiescent(ctx, worker); err != nil {
				return err
			}
		}
		if !found {
			if kind == "check" && fixtureMainNotStarted(attempt) {
				continue
			}
			return spec.Err(13, "prior Job creation has no durable server UID; recovery cannot infer worker termination")
		}
	}
	return nil
}
