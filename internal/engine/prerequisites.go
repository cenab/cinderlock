package engine

import (
	"context"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func licenseTimeError(requirement *spec.LicenseRequirement, now time.Time) error {
	if requirement == nil || requirement.ExpiresAt == "" {
		return nil
	}
	expires, err := time.Parse(time.RFC3339, requirement.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return spec.Err(10, "LICENSE_EXPIRED: declared offline entitlement validity is expired or invalid; follow the bundled vendor renewal procedure")
	}
	return nil
}

func prerequisiteCheckIDs(p spec.Plan, v *bundle.Verified) []string {
	if p.Kind != "Plan" && p.Kind != "RecoveryPlan" {
		return nil
	}
	ids := []string{}
	for _, check := range p.Checks {
		if check.Type == "endpoint" {
			ids = append(ids, check.ID)
		}
	}
	if requirement := v.Index.Lock.Release.Spec.License; requirement != nil && !slices.Contains(ids, requirement.Check) {
		ids = append(ids, requirement.Check)
	}
	return ids
}

func recordPrerequisiteFailure(result *spec.RunResult, checks []spec.CheckResult) {
	result.Domains["workflow"] = "blocked"
	mergeCheckResults(result, checks)
	for _, check := range checks {
		if check.Status != "pass" {
			result.Domains[check.Domain] = check.Status
		}
	}
}

func mergeCheckResults(result *spec.RunResult, checks []spec.CheckResult) {
	for _, check := range checks {
		index := slices.IndexFunc(result.Checks, func(prior spec.CheckResult) bool { return prior.ID == check.ID })
		if index < 0 {
			result.Checks = append(result.Checks, check)
		} else {
			result.Checks[index] = check
		}

	}
}

func (e *Engine) prerequisiteChecks(ctx context.Context, p spec.Plan, v *bundle.Verified, runID string, boundary func() (spec.TargetSnapshot, error)) ([]spec.CheckResult, error) {
	results := []spec.CheckResult{}
	for _, id := range prerequisiteCheckIDs(p, v) {
		if _, err := boundary(); err != nil {
			return results, err
		}
		var check *spec.Check
		for _, candidate := range p.Checks {
			if candidate.ID == id && (candidate.Required || slices.Contains(p.RequiredChecks, id)) {
				candidate.Required = true
				check = &candidate
				break
			}
		}
		if check == nil {
			return results, spec.Err(10, "required prerequisite check %s is absent from the signed recipe", id)
		}
		result := e.check(ctx, runID, *check, v)
		results = append(results, result)
		if result.Status != "pass" {
			code := 15
			attempt, err := e.Store.LatestOperation(ctx, runID, checkStepID(id))
			if err == nil && (attempt.State == "intent" || attempt.State == "uncertain") {
				code = 13
			}
			return results, spec.Err(code, "prerequisite check %s did not pass: %s", id, result.Reason)
		}
		if requirement := v.Index.Lock.Release.Spec.License; requirement != nil && id == requirement.Check {
			if err := e.entitlementFreshness(ctx, runID, *requirement); err != nil {
				results[len(results)-1].Status, results[len(results)-1].Reason = "blocked", err.Error()
				return results, err
			}
		}
	}
	return results, nil
}

func (e *Engine) entitlementFreshness(ctx context.Context, runID string, requirement spec.LicenseRequirement) error {
	if err := licenseTimeError(&requirement, time.Now()); err != nil {
		return err
	}
	step := checkStepID(requirement.Check)
	attempt, err := e.Store.LatestOperation(ctx, runID, step)
	if err != nil || attempt.State != "complete" {
		return spec.Err(13, "entitlement validation lacks its durable completed intent")
	}
	worker, err := e.operationWorker(ctx, runID, step, attempt.Attempt, step)
	if err != nil {
		return err
	}
	job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, worker.Name, metav1.GetOptions{})
	if err != nil || string(job.UID) != worker.UID || job.Status.CompletionTime == nil {
		return spec.Err(13, "entitlement validation lacks its original worker completion time")
	}
	// Reconciliation can update the journal long after this worker finished.
	completed := job.Status.CompletionTime.Time
	now := time.Now()
	if completed.After(now) || !now.Before(completed.Add(time.Duration(requirement.MaxAgeSeconds)*time.Second)) {
		return spec.Err(10, "ENTITLEMENT_STALE: original entitlement validation is stale or future-dated; follow vendor renewal and a fresh authorized recovery procedure, without rerunning this worker")
	}
	return nil
}
