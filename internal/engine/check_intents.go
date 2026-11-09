package engine

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type checkIntent struct {
	Type     string              `json:"type"`
	Check    spec.Check          `json:"check"`
	Fixtures []SeedVolumeBinding `json:"fixtures,omitempty"`
}

// This marker is written only after a definite fixture-verifier failure and
// before any application-worker create attempt. Missing workers are not evidence.
type checkOutcome struct {
	spec.CheckResult
	AcceptanceWorker string `json:"acceptanceWorker,omitempty"`
}

func fixtureMainNotStarted(attempt state.Operation) bool {
	if attempt.State != "failed" {
		return false
	}
	var outcome checkOutcome
	var intent checkIntent
	if spec.Decode(attempt.Evidence, &outcome) != nil || spec.Decode(attempt.Intent, &intent) != nil {
		return false
	}
	return outcome.AcceptanceWorker == "not_started" && len(intent.Check.Fixtures) > 0 && len(intent.Fixtures) == len(intent.Check.Fixtures) && outcome.ID == intent.Check.ID && outcome.Status == "fail"
}

func checkStepID(id string) string { return "@check/" + id }

func journalKind(body []byte) string {
	var header struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(body, &header)
	return header.Type
}

func checkIntentMatches(body []byte, check spec.Check) error {
	var intent checkIntent
	if err := spec.Decode(body, &intent); err != nil {
		return err
	}
	if len(intent.Fixtures) != len(check.Fixtures) {
		return spec.Err(13, "acceptance intent lacks the declared fixture provenance")
	}
	actual, err := spec.Digest(checkIntent{Type: intent.Type, Check: intent.Check})
	if err != nil {
		return err
	}
	expected, err := spec.Digest(checkIntent{Type: "check", Check: check})
	if err != nil {
		return err
	}
	if actual != expected {
		return spec.Err(13, "acceptance intent differs from signed plan check")
	}
	return nil
}

func (e *Engine) resumeCheck(ctx context.Context, p spec.Plan, attempt state.Operation) error {
	var check *spec.Check
	for _, candidate := range p.Checks {
		if checkStepID(candidate.ID) == attempt.StepID {
			candidate.Required = candidate.Required || slices.Contains(p.RequiredChecks, candidate.ID)
			check = &candidate
			break
		}
	}
	if check == nil {
		return spec.Err(13, "acceptance intent has no check in signed plan")
	}
	if err := checkIntentMatches(attempt.Intent, *check); err != nil {
		return err
	}
	if check.ObservationContract != nil {
		if err := spec.ValidateCheck(*check); err != nil {
			return err
		}
		if check.ObservationContract.Profile != e.Site.Spec.Profile {
			return spec.Err(13, "observation contract profile differs from selected site profile")
		}
	}
	if len(check.Fixtures) > 0 {
		bindings, err := fixtureIntentBindings(attempt.Intent)
		if err != nil {
			return err
		}
		if err := e.validateCheckFixtures(ctx, attempt.RunID, p, *check, bindings, true); err != nil {
			return err
		}
	}
	worker, err := e.operationWorker(ctx, attempt.RunID, attempt.StepID, attempt.Attempt, attempt.StepID)
	if err != nil {
		return err
	}
	status, err := e.inspectWorker(ctx, worker)
	if err != nil {
		return err
	}
	if status != "complete" {
		return spec.Err(13, "acceptance worker has not completed successfully; no duplicate is started")
	}
	result := spec.CheckResult{ID: check.ID, Domain: check.Domain, Required: check.Required, Status: "blocked", Evidence: "job/" + worker.Name}
	if result.Domain == "" {
		result.Domain = "workflow"
	}
	if check.ObservationContract != nil {
		result, err = e.completedCheckObservations(ctx, attempt, *check, result)
	}
	result = e.recordCheckResult(attempt, result, err, false)
	if result.Status == "blocked" {
		return spec.Err(13, "%s", result.Reason)
	}
	return nil
}

func (e *Engine) recordCheckResult(attempt state.Operation, result spec.CheckResult, checkErr error, notStarted bool) spec.CheckResult {
	outcome := "complete"
	result.Status = "pass"
	if checkErr != nil {
		result.Status, result.Reason, outcome = "blocked", checkErr.Error(), "uncertain"
		if spec.ExitCode(checkErr) == 14 {
			result.Status, outcome = "fail", "failed"
		}
	}
	persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var evidence any = result
	if notStarted && outcome == "failed" {
		evidence = checkOutcome{CheckResult: result, AcceptanceWorker: "not_started"}
	}
	if err := e.Store.Complete(persist, attempt, outcome, evidence); err != nil {
		result.Status = "blocked"
		result.Reason = "acceptance worker outcome could not be durably recorded"
		return result
	}
	run, err := e.Store.Run(persist, attempt.RunID)
	if err != nil || e.clusterRecord(persist, attempt.RunID, run.PlanDigest, outcome, evidence) != nil {
		result.Status = "blocked"
		result.Reason = "acceptance outcome cluster record could not be confirmed"
	}
	return result
}

func (e *Engine) observationPod(ctx context.Context, worker state.Worker, source *spec.ObservationSource) (*corev1.Pod, error) {
	if status, err := e.inspectWorker(ctx, worker); err != nil || status != "complete" {
		return nil, spec.Err(13, "observation worker identity or successful completion cannot be confirmed")
	}
	job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, worker.Name, metav1.GetOptions{})
	if err != nil {
		return nil, spec.Err(13, "observation Job cannot be inspected")
	}
	pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "cinderlock.dev/run=" + worker.RunID + ",cinderlock.dev/step=" + fingerprint(worker.Role)[7:23], Limit: 2})
	if err != nil || pods.Continue != "" || len(pods.Items) != 1 {
		return nil, spec.Err(13, "observations require one unique original completed Pod")
	}
	pod := &pods.Items[0]
	if _, err := workerPodRecipe(job, pod, worker); err != nil || pod.Status.Phase != corev1.PodSucceeded || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].Name != "operation" || pod.Status.ContainerStatuses[0].State.Terminated == nil || pod.Status.ContainerStatuses[0].State.Terminated.ExitCode != 0 {
		return nil, spec.Err(13, "observation Pod ownership, recipe or successful termination cannot be confirmed")
	}
	if source != nil && (source.JobName != worker.Name || source.JobUID != worker.UID || source.RecipeDigest != worker.RecipeDigest || source.PodName != pod.Name || source.PodUID != string(pod.UID)) {
		return nil, spec.Err(13, "observation source differs from the original bound Job or Pod")
	}
	return pod, nil
}

func (e *Engine) completedCheckObservations(ctx context.Context, attempt state.Operation, check spec.Check, result spec.CheckResult) (spec.CheckResult, error) {
	worker, err := e.operationWorker(ctx, attempt.RunID, attempt.StepID, attempt.Attempt, attempt.StepID)
	if err != nil {
		return result, err
	}
	if len(attempt.Evidence) > 0 {
		var prior checkOutcome
		if err := spec.Decode(attempt.Evidence, &prior); err != nil {
			return result, spec.Err(13, "recorded observation evidence cannot be decoded")
		}
		result.Observations = prior.Observations
	}
	var source *spec.ObservationSource
	if result.Observations != nil {
		source = &result.Observations.Source
	}
	pod, err := e.observationPod(ctx, worker, source)
	if err != nil {
		return result, err
	}
	if source == nil {
		result.Observations = &spec.CheckObservations{Basis: "application_reported", Contract: *check.ObservationContract, Source: spec.ObservationSource{JobName: worker.Name, JobUID: worker.UID, RecipeDigest: worker.RecipeDigest, PodName: pod.Name, PodUID: string(pod.UID)}}
		// Bind the Pod before transport so resume cannot select replacement logs.
		if err := e.Store.Complete(ctx, attempt, "uncertain", result); err != nil {
			return result, spec.Err(13, "observation source could not be durably recorded")
		}
	}
	output, readErr := e.podLogs(ctx, pod.Name)
	source = &result.Observations.Source
	if readErr == nil || len(output) > 0 {
		digest := spec.Hash(output)
		if source.OutputDigest != "" && source.OutputDigest != digest {
			return result, spec.Err(13, "original acceptance observation output changed")
		}
		source.OutputDigest = digest
	}
	if readErr != nil {
		return result, spec.Err(13, "original acceptance Pod observations could not be read within the bounded output profile")
	}
	report, passed, err := spec.EvaluateObservations(*check.ObservationContract, output)
	if err != nil {
		return result, spec.Err(13, "acceptance observations are missing, malformed or outside the declared bounded schema")
	}
	if _, err := e.observationPod(ctx, worker, source); err != nil {
		return result, err
	}
	result.Observations.Report = report
	if !passed {
		return result, spec.Err(14, "application-reported samples did not meet every declared assertion and budget")
	}
	return result, nil
}

func (e *Engine) recordedObservationCheck(ctx context.Context, attempt state.Operation, check spec.Check, blocked spec.CheckResult) spec.CheckResult {
	var stored checkOutcome
	if spec.Decode(attempt.Evidence, &stored) != nil || stored.ID != check.ID || stored.Domain != blocked.Domain || stored.Required != check.Required {
		blocked.Reason = "original observation result is unavailable or conflicts with the signed check"
		return blocked
	}
	result := stored.CheckResult
	failed := attempt.State == "failed" && result.Status == "fail"
	if !failed && (attempt.State != "complete" || result.Status != "pass" || result.Observations == nil || result.Observations.Report == nil) {
		blocked.Reason = "completed observation check has no original typed result"
		return blocked
	}
	worker, err := e.operationWorker(ctx, attempt.RunID, attempt.StepID, attempt.Attempt, attempt.StepID)
	if err == nil {
		_, err = e.inspectWorker(ctx, worker)
	}
	if err == nil && result.Observations != nil {
		if mustMatch, digestErr := spec.Digest(result.Observations.Contract); digestErr != nil {
			err = digestErr
		} else if expected, digestErr := spec.Digest(check.ObservationContract); digestErr != nil || mustMatch != expected {
			err = spec.Err(13, "recorded observation contract differs from signed check")
		} else {
			_, err = e.observationPod(ctx, worker, &result.Observations.Source)
		}
	}
	if err != nil && !failed {
		result.Status = "blocked"
		result.Reason = "original observation worker or source identity cannot be confirmed"
	}
	return result
}
