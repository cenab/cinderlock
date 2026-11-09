package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestGitOpsDataSuccessorRejectsMissingWorkersReplacementAndQueuedWriters(t *testing.T) {
	for _, change := range []string{"completed-job-missing", "data-uid-replaced", "queued-writer"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			f := newGitOpsDataUpgradeFixture(t, false)
			before := f.prepare(t)
			binding := f.adopt(t, false)
			switch change {
			case "completed-job-missing":
				workers, err := f.e.Store.Workers(ctx, before.RunID)
				if err != nil || len(workers) == 0 {
					t.Fatal(err)
				}
				if err := f.kube.BatchV1().Jobs("test").Delete(ctx, workers[0].Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			case "data-uid-replaced":
				claim, err := f.kube.CoreV1().PersistentVolumeClaims("test").Get(ctx, "application-data", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if err := f.kube.CoreV1().PersistentVolumeClaims("test").Delete(ctx, claim.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
				claim.UID = "replacement-data-uid"
				if _, err := f.kube.CoreV1().PersistentVolumeClaims("test").Create(ctx, claim, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "queued-writer":
				job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "foreign-pending-writer", Namespace: "test", UID: "foreign-writer-uid"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "writer", Image: "unrelated.invalid/writer", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}}, Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "application-data"}}}}}}}}
				if err := f.kube.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, "test"); err != nil {
					t.Fatal(err)
				}
			}
			f.kube.ClearActions()
			if _, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, binding); err == nil {
				t.Fatal("unproved or conflicting data state produced a successor plan", change)
			}
			original, _ := f.e.Store.Run(ctx, before.RunID)
			if !original.Active || original.State != "awaiting_adoption" {
				t.Fatal("failed planning released the predecessor gate")
			}
			for _, action := range f.kube.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("failed successor planning created a worker")
				}
			}
		})
	}
}

func TestGitOpsDataExpiredSuccessorApprovalKeepsOriginalGate(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsDataUpgradeFixture(t, false)
	before := f.prepare(t)
	binding := f.adopt(t, false)
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, binding)
	if err != nil {
		t.Fatal(err)
	}
	approval := f.approval(t, p)
	approval.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := spec.SignAuthorization(approval, f.key, "customer"); err != nil {
		t.Fatal(err)
	}
	f.kube.ClearActions()
	if _, err := f.e.Apply(ctx, p, f.v, f.policy, approval, false); spec.ExitCode(err) != 16 {
		t.Fatal("expired successor approval passed", err)
	}
	original, _ := f.e.Store.Run(ctx, before.RunID)
	if !original.Active {
		t.Fatal("expired successor approval released the predecessor")
	}
	for _, action := range f.kube.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			t.Fatal("expired approval created a worker")
		}
	}
}

func TestGitOpsDataHandoffResumesBeforeAnySuccessorWorker(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsDataUpgradeFixture(t, false)
	before := f.prepare(t)
	original, _ := f.e.Store.Run(ctx, before.RunID)
	binding := f.adopt(t, true)
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, binding)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := false
	f.kube.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		cm := action.(ktesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		if !interrupted && cm.Data["runID"] == before.RunID && cm.Data["state"] == "superseded" {
			interrupted = true
			return true, nil, errors.New("synthetic handoff interruption")
		}
		return false, nil, nil
	})
	f.kube.ClearActions()
	approval := f.approval(t, p)
	partial, err := f.e.Apply(ctx, p, f.v, f.policy, approval, false)
	if !interrupted || err == nil || partial.RunID == "" {
		t.Fatal("handoff fault was not exercised", err, partial)
	}
	for _, action := range f.kube.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			t.Fatal("successor worker preceded the completed cluster handoff")
		}
	}
	result, err := f.e.Resume(ctx, partial.RunID, f.v, f.policy, approval, false)
	if err != nil || result.RunID != partial.RunID || result.State != "succeeded" || result.Acceptance != "pass" {
		t.Fatal("recorded data handoff did not resume", err, result)
	}
	preserved, _ := f.e.Store.Run(ctx, before.RunID)
	if preserved.Active || string(preserved.Result) != string(original.Result) {
		t.Fatal("resumed handoff rewrote original data preparation")
	}
}

func TestGitOpsInitialDataFinalizationResumesAfterFloorAdvanced(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{data: true})
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := false
	f.kube.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		cm := action.(ktesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		if !interrupted && cm.Data["state"] == "succeeded" {
			interrupted = true
			return true, nil, errors.New("synthetic finalization interruption")
		}
		return false, nil, nil
	})
	approval := f.approval(t, p)
	partial, err := f.e.Apply(ctx, p, f.v, f.policy, approval, false)
	if !interrupted || err == nil || partial.RunID == "" {
		t.Fatal("finalization fault was not exercised", err)
	}
	accepted, err := f.e.Store.IsAcceptedRelease(ctx, p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel, p.Metadata.Sequence, p.BundleDigest)
	if err != nil || !accepted {
		t.Fatal("fault did not occur after the acceptance floor write", err)
	}
	result, err := f.e.Resume(ctx, partial.RunID, f.v, f.policy, approval, false)
	if err != nil || result.RunID != partial.RunID || result.Acceptance != "pass" {
		t.Fatal("initial data finalization could not resume its own accepted floor", err, result)
	}
}
