package catalog

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestRecordedGitOpsChecksReachComparisonAndPolicyReview(t *testing.T) {
	for _, kind := range []string{"GitOpsChecksPlan", "GitOpsDataChecksPlan"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			store, f := newPolicyFixture(t)
			o, err := store.Observation(ctx, "plant", "west", f.run.Digest)
			if err != nil {
				t.Fatal(err)
			}
			o.Plan.Kind = kind
			o.Plan.Operations = nil
			o.Run.PlanDigest, err = spec.Digest(o.Plan)
			if err != nil {
				t.Fatal(err)
			}
			f.plan = putPolicyRecord(t, store, "plant", "west", "Plan", o.Plan)
			f.run = putPolicyRecord(t, store, "plant", "west", "RunResult", o.Run)
			observed, err := store.Observation(ctx, "plant", "west", f.run.Digest)
			if err != nil {
				t.Fatal("recorded check-only phase was excluded", err)
			}
			comparison, err := CompareObservations(observed, observed, f.cfg.Now(), time.Hour)
			if err != nil || !comparison.Comparable || comparison.After.PlanKind != kind || comparison.After.Acceptance != "pass" {
				t.Fatal("recorded phase context lost", err, comparison)
			}
			pack := fixturePolicyPack(f.cfg.Now())
			stored := putPolicyRecord(t, store, "plant", "west", "PolicyPack", pack)
			f.cfg.PolicyPacks = []PolicyPackAdmission{{Project: "plant", Site: "west", Digest: stored.Digest}}
			h := policyHandler(t, f.cfg)
			evaluation := readPolicyEvaluation(t, h, policyPath(f, true))
			if !evaluation.Satisfied {
				t.Fatal("permitted recorded check-only phase failed policy", evaluation)
			}
			o.Plan.RequiredChecks = nil
			o.Run.Checks[0].Required = false
			o.Run.Acceptance = "not_established"
			o.Run.PlanDigest, err = spec.Digest(o.Plan)
			if err != nil {
				t.Fatal(err)
			}
			f.plan = putPolicyRecord(t, store, "plant", "west", "Plan", o.Plan)
			f.run = putPolicyRecord(t, store, "plant", "west", "RunResult", o.Run)
			denied := readPolicyEvaluation(t, h, policyPath(f, true))
			if denied.Satisfied {
				t.Fatal("GitOps kind bypassed the pack's required workflow")
			}
		})
	}
}

func TestRecoveryObservationRejectsAnotherSourceRun(t *testing.T) {
	store, f := newPolicyFixture(t)
	o, err := store.Observation(context.Background(), "plant", "west", f.run.Digest)
	if err != nil {
		t.Fatal(err)
	}
	o.Plan.Kind, o.Plan.SourceRun = "RecoveryPlan", "original-failed-run"
	o.Run.SourceRun = "another-failed-run"
	o.Run.PlanDigest, err = spec.Digest(o.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SubjectForObservation(o); err == nil {
		t.Fatal("conflicting recovery source became a catalog subject")
	}
}

func TestAwaitingAdoptionCanQueueLocalNoticeWithoutAcceptance(t *testing.T) {
	ctx := context.Background()
	store, f := newPolicyFixture(t)
	var run spec.RunResult
	if err := spec.Decode(f.run.Record.Body, &run); err != nil {
		t.Fatal(err)
	}
	run.State, run.Acceptance = "awaiting_adoption", "not_established"
	f.run = putPolicyRecord(t, store, "plant", "west", "RunResult", run)
	f.cfg.NotificationRules = []NotificationRule{{ID: "adoption", Project: "plant", Site: "west", States: []string{"awaiting_adoption"}}}
	h, err := NewHandler(f.cfg)
	if err != nil {
		t.Fatal("waiting state cannot configure its local notice", err)
	}
	r := request(h, http.MethodPost, "/api/v1/notification-queues", "operator-token", "awaiting", map[string]any{"project": "plant", "site": "west", "runDigest": f.run.Digest})
	if r.Code != http.StatusOK {
		t.Fatalf("waiting notice unavailable: %d %s", r.Code, r.Body.String())
	}
	notes, err := store.QueueNotifications(ctx, "operator", "plant", "west", f.run.Digest, f.cfg.NotificationRules, f.cfg.Now())
	if err != nil || len(notes) != 1 || notes[0].Notification.Summary.State != run.State || notes[0].Notification.Summary.Acceptance != "not_established" {
		t.Fatal("waiting notice changed original acceptance", err, notes)
	}
	retained, err := store.Get(ctx, "plant", "west", "RunResult", f.run.Digest)
	if err != nil || string(retained.Record.Body) != string(f.run.Record.Body) {
		t.Fatal("local notification rewrote the recorded result", err)
	}
}
