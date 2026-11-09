package engine

import (
	"context"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func TestGitOpsNativeTransferRechecksBeforeStartingVerifier(t *testing.T) {
	for _, change := range []string{"source", "authorization"} {
		t.Run(change, func(t *testing.T) {
			f := newGitOpsExecutionFixture(t, true, change)
			if f.prepared == nil || f.preparationError == nil {
				t.Fatal("changed boundary did not block preparation", f.preparationError)
			}
			workers, err := f.e.Store.Workers(context.Background(), f.prepared.RunID)
			if err != nil || len(workers) != 1 || workers[0].Role != "seed-model" {
				t.Fatalf("new verifier started after %s changed during transfer: %v %#v", change, err, workers)
			}
		})
	}
}

func TestGitOpsPreparationResumesOriginalTransferIntoUsableReceipt(t *testing.T) {
	f := newGitOpsExecutionFixture(t, true, "authorization")
	if f.prepared == nil || f.preparationError == nil {
		t.Fatal("experiment did not stop after the original transfer")
	}
	ctx := context.Background()
	before, err := f.e.Store.Workers(ctx, f.prepared.RunID)
	if err != nil || len(before) != 1 {
		t.Fatal("experiment must retain only its original receiver", err, before)
	}
	result, err := f.e.Resume(ctx, f.prepared.RunID, f.v, f.policy, f.approval(t, f.preparationPlan), false)
	if err != nil || result.State != "gitops_prepared" || result.Acceptance != "not_established" {
		t.Fatalf("original completed transfer could not resume: %v %#v", err, result)
	}
	after, err := f.e.Store.Workers(ctx, result.RunID)
	if err != nil || len(after) != 2 || after[0] != before[0] {
		t.Fatal("resume replaced the original receiver or duplicated a worker", err, after)
	}
	if _, err := f.e.gitOpsPreparationReference(ctx, spec.GitOpsRunReference{RunID: result.RunID}, f.v, f.sitePath, f.policy); err != nil {
		t.Fatal("resumed preparation produced an unusable cross-run receipt", err)
	}
	// Simulate the durable-operation/result-persistence gap: original completed
	// intents and workers survive, while the last run result lacks its step.
	partial := result
	partial.Steps = nil
	if err := f.e.Store.SetState(ctx, result.RunID, "needs_reconciliation", true, partial); err != nil {
		t.Fatal(err)
	}
	restored, err := f.e.Resume(ctx, result.RunID, f.v, f.policy, f.approval(t, f.preparationPlan), false)
	if err != nil || restored.State != "gitops_prepared" || len(restored.Steps) != 1 || restored.Steps[0].Status != "pass" {
		t.Fatal("completed original intent did not reconstruct its preparation result", err, restored)
	}
	afterRestore, err := f.e.Store.Workers(ctx, result.RunID)
	if err != nil || len(afterRestore) != len(after) {
		t.Fatal("result reconstruction created another worker", err, afterRestore)
	}
}

func TestGitOpsChecksRejectAcceptedReleaseReplay(t *testing.T) {
	for _, when := range []string{"planning", "after-plan"} {
		t.Run(when, func(t *testing.T) {
			f := newGitOpsExecutionFixture(t, false)
			ctx := context.Background()
			plan, err := f.e.GitOpsChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
			if err != nil || !plan.Executable {
				t.Fatal("control plan is not executable", err)
			}
			if err := f.e.Store.AcceptRelease(ctx, plan.Snapshot.TargetID, plan.Metadata.Application, plan.Metadata.Channel, plan.Metadata.Sequence+1, spec.Hash([]byte("newer accepted release"))); err != nil {
				t.Fatal(err)
			}
			if when == "planning" {
				plan, err = f.e.GitOpsChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
				if err == nil && plan.Executable {
					t.Fatal("older application sequence still produced an executable checks plan")
				}
				return
			}
			result, err := f.e.Apply(ctx, plan, f.v, f.policy, f.approval(t, plan), false)
			if err == nil || result.Acceptance == "pass" {
				t.Fatal("older application sequence passed after the accepted floor advanced", err, result)
			}
		})
	}
}

func TestGitOpsSeedsFollowSignedDAGInsteadOfDeclarationOrder(t *testing.T) {
	seeds := []spec.Operation{{ID: "later", Type: "seed", Asset: "later", PVC: "later", MountPath: "/models", StorageBytes: 1, DependsOn: []string{"earlier"}}, {ID: "earlier", Type: "seed", Asset: "earlier", PVC: "earlier", MountPath: "/models", StorageBytes: 1}}
	v := &bundle.Verified{Index: spec.BundleIndex{Lock: spec.ReleaseLock{Release: spec.Release{Spec: spec.ReleaseSpec{Operations: seeds}}}}}
	selected, _, err := gitOpsSignedSeeds(v)
	if err != nil || len(selected) != 2 || selected[0].ID != "earlier" || selected[1].ID != "later" {
		t.Fatal("valid signed seed dependency order was lost", err, selected)
	}
}
