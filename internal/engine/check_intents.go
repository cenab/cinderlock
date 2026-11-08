package engine

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

type checkIntent struct {
	Type     string           `json:"type"`
	Check    spec.Check       `json:"check"`
	Fixtures []fixtureBinding `json:"fixtures,omitempty"`
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
	return e.Store.Complete(ctx, attempt, "complete", spec.CheckResult{ID: check.ID, Domain: check.Domain, Required: check.Required, Status: "pass", Evidence: "job/" + worker.Name})
}
