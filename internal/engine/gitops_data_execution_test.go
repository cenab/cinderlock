package engine

import (
	"context"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestGitOpsInitialDataChecksAcceptExplicitExistingClaim(t *testing.T) {
	for _, models := range []bool{false, true} {
		name := "data"
		if models {
			name = "models-and-data"
		}
		t.Run(name, func(t *testing.T) {
			f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{models: models, data: true})
			ctx := context.Background()
			p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
			if err != nil || !p.Executable {
				t.Fatalf("initial data plan failed: %v %+v", err, p.Findings)
			}
			result, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
			if err != nil || result.State != "succeeded" || result.Acceptance != "pass" {
				t.Fatalf("initial data workflows failed: %v %+v", err, result)
			}
			record, err := f.e.Store.Run(ctx, result.RunID)
			if err != nil || record.Active {
				t.Fatal("initial acceptance retained its mutation gate", err)
			}
			floor, err := f.e.Store.ReleaseFloor(ctx, result.TargetID, p.Metadata.Application, p.Metadata.Channel)
			if err != nil || floor != p.Metadata.Sequence {
				t.Fatal("initial data acceptance did not advance its exact floor", floor, err)
			}
			if models && gitOpsSnapshotFact(p, "gitops/prepared-evidence/model-v2") == "" {
				t.Fatal("accepted native model identities were not retained for the next data transition")
			}
			if _, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding); err == nil {
				t.Fatal("initial data mode bypassed an already accepted application")
			}
		})
	}
}

func TestGitOpsDataUpgradeTransfersHeldGateUnderRotatedAuthority(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsDataUpgradeFixture(t, false)
	before := f.prepare(t)
	original, err := f.e.Store.Run(ctx, before.RunID)
	if err != nil || !original.Active {
		t.Fatal("awaiting adoption released the data gate", err)
	}
	if _, err := f.e.acquire(ctx, "unrelated-run"); err == nil {
		t.Fatal("another application mutation passed the waiting cluster gate")
	}
	floor, err := f.e.Store.ReleaseFloor(ctx, before.TargetID, "app", "stable")
	if err != nil || floor != f.baseline.Metadata.Sequence {
		t.Fatal("preparation accepted the target release", floor, err)
	}
	binding := f.adopt(t, true)
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, binding)
	if err != nil || !p.Executable {
		t.Fatal("post-adoption plan", err, p.Findings)
	}
	result, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
	if err != nil || result.State != "succeeded" || result.Acceptance != "pass" {
		t.Fatal("post-adoption acceptance", err, result)
	}
	previous, _ := f.e.Store.Run(ctx, before.RunID)
	current, _ := f.e.Store.Run(ctx, result.RunID)
	if previous.Active || current.Active || string(previous.Result) != string(original.Result) {
		t.Fatal("success rewrote predecessor evidence or retained the gate")
	}
	floor, err = f.e.Store.ReleaseFloor(ctx, result.TargetID, "app", "stable")
	if err != nil || floor != p.Metadata.Sequence {
		t.Fatal("accepted target floor was not recorded", floor, err)
	}
}

func TestGitOpsDataRecoveryRetainsFailedAcceptanceAndUsesFreshGate(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsDataUpgradeFixture(t, false)
	f.prepare(t)
	binding := f.adopt(t, true)
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, binding)
	if err != nil || !p.Executable {
		t.Fatal(err, p.Findings)
	}
	failWorkflow := true
	f.kube.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		if !failWorkflow || job.Spec.Template.Spec.Containers[0].Command[0] != "/app/check" {
			return false, nil, nil
		}
		job.UID = types.UID("failed-" + job.Name)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
		if err := f.kube.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, "test"); err != nil {
			t.Fatal(err)
		}
		return true, job, nil
	})
	failed, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
	if err == nil || failed.State != "failed" || failed.Acceptance == "pass" {
		t.Fatal("required failed workflow did not retain failure", err, failed)
	}
	original, err := f.e.Store.Run(ctx, failed.RunID)
	if err != nil || !original.Active {
		t.Fatal("failed postcheck released the data gate", err)
	}
	floor, err := f.e.Store.ReleaseFloor(ctx, failed.TargetID, "app", "stable")
	if err != nil || floor != f.baseline.Metadata.Sequence {
		t.Fatal("failed upgrade advanced its release floor", floor, err)
	}
	failWorkflow = false
	recovery, err := f.e.GitOpsDataRecoveryPlan(ctx, failed.RunID, "restore", f.v, "verified.cinder", f.sitePath, f.policy, spec.GitOpsPlanBinding{ManifestPath: f.futureManifest, Contract: &f.contract})
	if err != nil || !recovery.Executable {
		t.Fatal("same-source recovery plan", err, recovery.Findings)
	}
	restored, err := f.e.Apply(ctx, recovery, f.v, f.policy, f.approval(t, recovery), false)
	if err != nil || restored.State != "recovered" || restored.Acceptance != "pass" || restored.SourceRun != failed.RunID {
		t.Fatal("same-source recovery did not use the exact failed gate", err, restored)
	}
	preserved, _ := f.e.Store.Run(ctx, failed.RunID)
	current, _ := f.e.Store.Run(ctx, restored.RunID)
	if preserved.Active || current.Active || string(preserved.Result) != string(original.Result) || preserved.State != "failed" {
		t.Fatal("recovery rewrote failed acceptance or retained the gate")
	}
	if _, _, _, err := f.e.acceptedGitOpsReference(ctx, spec.GitOpsRunReference{RunID: restored.RunID}); err != nil {
		t.Fatal("separately accepted recovery could not serve as the next operational baseline", err)
	}
}

func TestGitOpsDataPreparationObservesOldModelsAfterPolicyRotation(t *testing.T) {
	f := newGitOpsDataUpgradeFixture(t, true)
	f.rotateAuthority(t)
	result := f.prepare(t)
	if result.State != "awaiting_adoption" || result.Acceptance != "not_established" {
		t.Fatal("historical model evidence changed preparation acceptance", result)
	}
}
