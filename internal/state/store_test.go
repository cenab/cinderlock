package state

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func fixtureRun(id string) Run {
	return Run{ID: id, Application: "app", Namespace: "ns", TargetID: "cluster/ns", PlanDigest: "sha256:plan", BundleDigest: "sha256:bundle", State: "acquiring", Plan: []byte(`{"plan":1}`), Site: []byte(`{"site":1}`)}
}

func TestIntentSurvivesReopenAndCannotBeBlindlyOverwritten(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRun(ctx, fixtureRun("run-1")); err != nil {
		t.Fatal(err)
	}
	op, err := s.Intent(ctx, "run-1", "migration", map[string]string{"operation": "unique"}, "job/unique")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ops, err := s.Operations(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].State != "intent" {
		t.Fatalf("lost intent: %#v", ops)
	}
	if err := s.Complete(ctx, op, "complete", map[string]bool{"verified": true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, op, "failed", nil); err == nil {
		t.Fatal("finalized outcome overwritten")
	}
}

func TestActiveRunAndAuthorizationReplay(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateRun(ctx, fixtureRun("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRun(ctx, fixtureRun("two")); !errors.Is(err, ErrActiveRun) {
		t.Fatalf("expected active conflict, got %v", err)
	}
	if err := s.ConsumeAuthorization(ctx, "approval", "p", "one", "policy", "expiry"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeAuthorization(ctx, "approval", "p", "one", "policy", "expiry"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, "one", "succeeded", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRun(ctx, fixtureRun("two")); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeAuthorization(ctx, "approval", "p", "two", "policy", "expiry"); !errors.Is(err, ErrAuthorizationUsed) {
		t.Fatalf("approval replayed: %v", err)
	}
}

func TestHighWaterNeverMovesBackwards(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.AcceptRelease(ctx, "target", "app", "stable", 10, "digest"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptRelease(ctx, "target", "app", "stable", 2, "old"); err != nil {
		t.Fatal(err)
	}
	n, err := s.ReleaseFloor(ctx, "target", "app", "stable")
	if err != nil || n != 10 {
		t.Fatalf("floor=%d err=%v", n, err)
	}
}

func TestRunAdmissionAndNonceConsumptionAreAtomic(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	approval := &Authorization{Nonce: "one-use", PolicyDigest: "policy", ExpiresAt: "expiry"}
	if err := s.AdmitRun(ctx, fixtureRun("first"), "", approval); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, "first", "succeeded", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitRun(ctx, fixtureRun("rejected"), "", approval); !errors.Is(err, ErrAuthorizationUsed) {
		t.Fatalf("reused nonce accepted: %v", err)
	}
	if _, err := s.Run(ctx, "rejected"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rejected approval left a phantom run: %v", err)
	}
	if events, err := s.Events(ctx, "rejected"); err != nil || len(events) != 0 {
		t.Fatalf("rejected admission left events: %#v %v", events, err)
	}
	fresh := &Authorization{Nonce: "fresh", PolicyDigest: "policy", ExpiresAt: "expiry"}
	if err := s.AdmitRun(ctx, fixtureRun("fresh-run"), "", fresh); err != nil {
		t.Fatalf("replay rejection blocked fresh authorization: %v", err)
	}
	if err := s.AdmitRun(ctx, fixtureRun("recovery-rejected"), "fresh-run", approval); !errors.Is(err, ErrAuthorizationUsed) {
		t.Fatalf("recovery reused old nonce: %v", err)
	}
	source, err := s.Run(ctx, "fresh-run")
	if err != nil || !source.Active {
		t.Fatalf("rejected recovery released unresolved gate: %#v %v", source, err)
	}
	if _, err := s.Run(ctx, "recovery-rejected"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rejected recovery persisted: %v", err)
	}
}

func TestTransitionEventsCommitWithTheirState(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateRun(ctx, fixtureRun("run")); err != nil {
		t.Fatal(err)
	}
	intent, err := s.Intent(ctx, "run", "migration", map[string]string{"id": "migration"}, "job/migration")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER reject_outcome_event BEFORE INSERT ON events WHEN NEW.type='operation_outcome' BEGIN SELECT RAISE(ABORT,'event write failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, intent, "complete", map[string]bool{"confirmed": true}); err == nil {
		t.Fatal("outcome committed without its event")
	}
	operations, err := s.Operations(ctx, "run")
	if err != nil || len(operations) != 1 || operations[0].State != "intent" {
		t.Fatalf("event failure did not roll back outcome: %#v %v", operations, err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER reject_outcome_event`); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, intent, "complete", map[string]bool{"confirmed": true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCheckpoint(ctx, "run", "checkpoint", map[string]string{"state": "expected"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, "run", "succeeded", false, nil); err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"run_created", "operation_intent", "operation_outcome", "checkpoint", "run_state"}
	if len(events) != len(expected) {
		t.Fatalf("missing transitions: %#v", events)
	}
	for i, event := range events {
		if event.Seq != int64(i+1) || event.Type != expected[i] {
			t.Fatalf("unexpected event sequence: %#v", events)
		}
	}
}

func TestLegacySchemaMigrationPreservesRunButDoesNotInventWorkerIdentity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRun(ctx, fixtureRun("legacy")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TABLE workers; DROP TABLE run_protocols; PRAGMA user_version=1;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run, err := s.Run(ctx, "legacy")
	if err != nil || !run.Active {
		t.Fatalf("schema migration lost unresolved run: %#v %v", run, err)
	}
	if err := s.WorkerProtocol(ctx, "legacy"); err == nil {
		t.Fatal("migration invented trusted worker identities")
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != 2 {
		t.Fatalf("version=%d error=%v", version, err)
	}
}
