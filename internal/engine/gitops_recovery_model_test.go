package engine

import (
	"context"
	"os"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestGitOpsDataRecoveryRetainsOriginalModelReaders(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{models: true, data: true})
	f.e.Site.Spec.BackupRef = "external-test-backup"
	f.binding.Data.BackupRef = f.e.Site.Spec.BackupRef
	if err := os.WriteFile(f.sitePath, mustCanonical(t, f.e.Site), 0600); err != nil {
		t.Fatal(err)
	}
	r := &f.v.Index.Lock.Release
	var operations []spec.Operation
	dependency := ""
	for _, id := range []string{"restore-quiesce", "restore-data", "restore-writes"} {
		op := spec.Operation{ID: id, Type: "job", Image: "runner", Command: []string{"/app/" + id}, PVC: "application-data", MountPath: "/data", TimeoutSeconds: 5, Idempotent: true, Script: fixtureScript("workflow")}
		if dependency != "" {
			op.DependsOn = []string{dependency}
		}
		operations = append(operations, op)
		dependency = id
	}
	check := r.Spec.Checks[0]
	check.Fixtures = nil
	r.Spec.Recovery = []spec.Recovery{{ID: "restore", ToRelease: r.Metadata.Version, DataRevision: f.e.Site.Spec.DataRevision, RequiresBackup: true, GitOpsData: &spec.GitOpsDataProcedures{PVC: "application-data", Quiesce: "restore-quiesce", Resume: "restore-writes"}, Operations: operations, Checks: []spec.Check{check}}}
	r.Spec.Transitions[0].Recovery = "restore"
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil || !p.Executable {
		t.Fatal("initial model/data plan", err, p.Findings)
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
		t.Fatal("failed workflow lost its gate", err)
	}
	workers, err := f.e.Store.Workers(ctx, failed.RunID)
	if err != nil {
		t.Fatal(err)
	}
	readers := 0
	var modelJob *batchv1.Job
	for _, worker := range workers {
		job, err := f.kube.BatchV1().Jobs("test").Get(ctx, worker.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if gitOpsUsesClaim(job.Spec.Template.Spec, "model-v2") {
			readers++
			modelJob = job.DeepCopy()
			if _, err := gitOpsClaimMounts(job.Spec.Template.Spec, "model-v2", "", true); err != nil {
				t.Fatal("original verifier is not read-only", err)
			}
		}
	}
	if readers == 0 {
		t.Fatal("control must retain an original model reader")
	}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-model-reader", Namespace: "test", UID: "original-model-reader-uid", Labels: modelJob.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: modelJob.Name, UID: modelJob.UID, Controller: &yes}}}, Spec: *modelJob.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{Name: modelJob.Spec.Template.Spec.Containers[0].Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}}}
	if _, err := f.kube.CoreV1().Pods("test").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"pending", "complete"} {
		t.Run("unknown-"+outcome, func(t *testing.T) {
			foreign := modelJob.DeepCopy()
			foreign.Name, foreign.UID, foreign.ResourceVersion = "unknown-model-reader", "unknown-model-reader-uid", ""
			foreign.Status = batchv1.JobStatus{}
			if outcome == "complete" {
				foreign.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
			}
			if err := f.kube.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), foreign, "test"); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.kube.Tracker().Delete(batchv1.SchemeGroupVersion.WithResource("jobs"), "test", foreign.Name); err != nil {
					t.Error(err)
				}
			}()
			f.kube.ClearActions()
			candidate, err := f.e.GitOpsDataRecoveryPlan(ctx, failed.RunID, "restore", f.v, "verified.cinder", f.sitePath, f.policy, spec.GitOpsPlanBinding{ManifestPath: f.binding.ManifestPath, Contract: &f.contract})
			if err == nil && candidate.Executable {
				t.Fatal("unknown model consumer admitted", outcome)
			}
			for _, action := range f.kube.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("failed planning created a worker")
				}
			}
		})
	}
	failWorkflow = false
	recovery, err := f.e.GitOpsDataRecoveryPlan(ctx, failed.RunID, "restore", f.v, "verified.cinder", f.sitePath, f.policy, spec.GitOpsPlanBinding{ManifestPath: f.binding.ManifestPath, Contract: &f.contract})
	if err != nil || !recovery.Executable {
		t.Fatal("original model reader blocked recovery planning", err, recovery.Findings)
	}
	restored, err := f.e.Apply(ctx, recovery, f.v, f.policy, f.approval(t, recovery), false)
	if err != nil || restored.State != "recovered" || restored.Acceptance != "pass" || restored.SourceRun != failed.RunID {
		t.Fatal("recovery did not retain its failed predecessor", err, restored)
	}
	preserved, _ := f.e.Store.Run(ctx, failed.RunID)
	if preserved.Active || preserved.State != "failed" || string(preserved.Result) != string(original.Result) {
		t.Fatal("recovery rewrote its original failure")
	}
}
