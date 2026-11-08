package engine

import (
	"context"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestApplyFinalCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*corev1.Secret, *appsv1.Deployment)
		drift  bool
	}{
		{
			name: "selected-secret-data-with-same-uid",
			mutate: func(secret *corev1.Secret, _ *appsv1.Deployment) {
				secret.Data["token"] = []byte("rotated-token")
			},
			drift: true,
		},
		{
			name: "healthy-managed-deployment-uid-replacement",
			mutate: func(_ *corev1.Secret, deployment *appsv1.Deployment) {
				deployment.UID = "replacement-deployment-uid"
			},
			drift: true,
		},
		{
			name: "resource-version-and-status-only-churn",
			mutate: func(secret *corev1.Secret, deployment *appsv1.Deployment) {
				secret.ResourceVersion = "2"
				deployment.ResourceVersion = "2"
				deployment.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, Reason: "MinimumReplicasAvailable"}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			e, client, policy := fixture(t)
			e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"credentials": {Name: "credentials", Key: "token"}}
			if _, err := client.CoreV1().Secrets("test").Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "test", UID: "credentials-uid", ResourceVersion: "1"},
				Type:       corev1.SecretTypeOpaque,
				Data:       map[string][]byte{"token": []byte("original-token")},
			}, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			p, v := fixturePlan(t, e, policy)
			v.Index.Lock.Release.Spec.Checks[0].SecretRefs = []string{"credentials"}
			v.Index.Lock.Release.Spec.Checks[0].Script.Inputs = append(v.Index.Lock.Release.Spec.Checks[0].Script.Inputs, "credentials Secret token")
			chart := chartFixture(t, e)
			v.Root = chart.Root
			v.Index.Lock.Assets = append(v.Index.Lock.Assets, chart.Index.Lock.Assets...)
			nativeHelm := e.HelmRunner
			e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
				if args[0] == "template" {
					return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: app}\ndata: {mode: test}\n"), nil
				}
				return nativeHelm(ctx, args...)
			}
			var err error
			p, err = e.Plan(ctx, v, p.BundlePath, p.SitePath, policy)
			if err != nil || !p.Executable {
				t.Fatalf("test release is not executable: %v %#v", err, p.Findings)
			}
			lastCheck := p.Checks[len(p.Checks)-1]
			finalJob := ""
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				job.UID = types.UID("uid-" + job.Name)
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				if job.Name != jobName(job.Labels["cinderlock.dev/run"], checkStepID(lastCheck.ID)) {
					return false, nil, nil
				}
				if finalJob != "" {
					t.Fatal("final check started more than once")
				}
				finalJob = job.Name
				// Use the tracker because the fake client holds its lock during reactors.
				secrets := corev1.SchemeGroupVersion.WithResource("secrets")
				secretObject, err := client.Tracker().Get(secrets, "test", "credentials")
				if err != nil {
					t.Fatal(err)
				}
				deployments := appsv1.SchemeGroupVersion.WithResource("deployments")
				deploymentObject, err := client.Tracker().Get(deployments, "test", "app")
				if err != nil {
					t.Fatal(err)
				}
				test.mutate(secretObject.(*corev1.Secret), deploymentObject.(*appsv1.Deployment))
				if err := client.Tracker().Update(secrets, secretObject, "test"); err != nil {
					t.Fatal(err)
				}
				if err := client.Tracker().Update(deployments, deploymentObject, "test"); err != nil {
					t.Fatal(err)
				}
				return false, nil, nil
			})
			result, applyErr := e.Apply(ctx, p, v, policy, nil, true)
			if finalJob == "" {
				t.Fatalf("mutation never reached the final authored check: %v %#v", applyErr, result)
			}
			if len(result.Checks) != 1 || result.Checks[0].ID != lastCheck.ID || result.Checks[0].Status != "pass" || result.Checks[0].Evidence != "job/"+finalJob {
				t.Fatalf("final check's successful evidence was lost: %v %#v", applyErr, result.Checks)
			}
			attempt, err := e.Store.LatestOperation(ctx, result.RunID, checkStepID(lastCheck.ID))
			if err != nil || attempt.State != "complete" {
				t.Fatalf("final check's durable completion was lost: %v %#v", err, attempt)
			}
			var evidence spec.CheckResult
			if err := spec.Decode(attempt.Evidence, &evidence); err != nil {
				t.Fatal(err)
			}
			if evidence.ID != lastCheck.ID || evidence.Status != "pass" || evidence.Evidence != "job/"+finalJob {
				t.Errorf("final check's durable evidence was lost: %#v", evidence)
			}
			floor, err := e.Store.ReleaseFloor(ctx, p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
			if err != nil {
				t.Fatal(err)
			}
			if test.drift {
				if spec.ExitCode(applyErr) != 11 || result.Acceptance == "pass" {
					t.Errorf("final-check drift was accepted: code=%d error=%v state=%s acceptance=%s", spec.ExitCode(applyErr), applyErr, result.State, result.Acceptance)
				}
				if floor != 0 {
					t.Errorf("final-check drift advanced accepted release floor to %d, want 0", floor)
				}
			} else {
				if applyErr != nil || result.State != "succeeded" || result.Acceptance != "pass" {
					t.Errorf("bookkeeping-only churn prevented acceptance: %v %#v", applyErr, result)
				}
				if floor != 2 {
					t.Errorf("accepted release floor = %d, want 2", floor)
				}
			}
		})
	}
}
