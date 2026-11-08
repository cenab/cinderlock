package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func workerFixture(t *testing.T) (*Engine, *fake.Clientset, spec.TrustPolicy, spec.Plan, *bundle.Verified, state.Operation) {
	t.Helper()
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	plan, _ := spec.Canonical(p)
	site, _ := spec.Canonical(e.Site)
	digest, _ := spec.Digest(p)
	if err := e.Store.CreateRun(context.Background(), state.Run{ID: "worker-run", Application: "app", Namespace: "test", TargetID: p.Snapshot.TargetID, PlanDigest: digest, BundleDigest: v.Digest, Plan: plan, Site: site}); err != nil {
		t.Fatal(err)
	}
	intent, err := e.Store.Intent(context.Background(), "worker-run", p.Operations[0].ID, p.Operations[0], jobName("worker-run", p.Operations[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	return e, client, policy, p, v, intent
}

func completeWorkers(client *fake.Clientset) {
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
}

func TestWorkerIdentityRejectsReplacementAndChangedRecipe(t *testing.T) {
	e, client, policy, p, v, intent := workerFixture(t)
	completeWorkers(client)
	operation := p.Operations[0]
	name, err := e.operation(context.Background(), p, "worker-run", operation, v, policy)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := e.Store.Worker(context.Background(), "worker-run", operation.ID, intent.Attempt, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := e.inspectWorker(context.Background(), worker); err != nil || status != "complete" {
		t.Fatalf("original worker rejected: %s %v", status, err)
	}
	job, _ := client.BatchV1().Jobs("test").Get(context.Background(), name, metav1.GetOptions{})
	job.Spec.Template.Spec.ServiceAccountName = "default"
	job.Spec.Template.Spec.DNSPolicy = corev1.DNSClusterFirst
	job.Spec.Template.Spec.SchedulerName = "default-scheduler"
	job.Spec.Template.Spec.Containers[0].TerminationMessagePath = "/dev/termination-log"
	job.Spec.Template.Spec.Containers[0].TerminationMessagePolicy = corev1.TerminationMessageReadFile
	if _, err := client.BatchV1().Jobs("test").Update(context.Background(), job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.inspectWorker(context.Background(), worker); err != nil {
		t.Fatalf("harmless API defaults rejected: %v", err)
	}
	job.UID = "replacement"
	if _, err := client.BatchV1().Jobs("test").Update(context.Background(), job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.inspectWorker(context.Background(), worker); spec.ExitCode(err) != 13 {
		t.Fatalf("replacement completion trusted: %v", err)
	}
	job.UID = types.UID(worker.UID)
	job.Spec.Template.Spec.Containers[0].Command = []string{"/different-command"}
	if _, err := client.BatchV1().Jobs("test").Update(context.Background(), job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.inspectWorker(context.Background(), worker); spec.ExitCode(err) != 13 {
		t.Fatalf("different recipe trusted: %v", err)
	}
}

func TestResumeDoesNotTrustReplacementMigrationJob(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*batchv1.Job)
	}{
		{"original", func(*batchv1.Job) {}},
		{"replacement", func(j *batchv1.Job) { j.UID = "replacement" }},
		{"cpu-request", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("200m")
		}},
		{"cpu-limit", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("200m")
		}},
		{"memory-request", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse("512Mi")
		}},
		{"memory-limit", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] = resource.MustParse("512Mi")
		}},
		{"ephemeral-request", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceEphemeralStorage] = resource.MustParse("128Mi")
		}},
		{"ephemeral-limit", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceEphemeralStorage] = resource.MustParse("128Mi")
		}},
		{"temporary", func(j *batchv1.Job) {
			j.Spec.Template.Spec.Volumes[0].EmptyDir.SizeLimit = resource.NewQuantity(8<<20, resource.BinarySI)
		}},
		{"deadline", func(j *batchv1.Job) { (*j.Spec.ActiveDeadlineSeconds)++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			e, client, policy, p, v, intent := workerFixture(t)
			completeWorkers(client)
			ctx := context.Background()
			name, err := e.operation(ctx, p, "worker-run", p.Operations[0], v, policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Store.Complete(ctx, intent, "uncertain", map[string]string{"lost": "outcome acknowledgement"}); err != nil {
				t.Fatal(err)
			}
			if err := e.clusterRecord(ctx, "worker-run", mustDigest(t, p), "uncertain", intent); err != nil {
				t.Fatal(err)
			}
			job, err := client.BatchV1().Jobs("test").Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			assertJobBudget(t, job, p.Operations[0].Script.Resources, p.Operations[0].TimeoutSeconds)
			change.edit(job)
			if _, err := client.BatchV1().Jobs("test").Update(ctx, job, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			result, err := e.Resume(ctx, "worker-run", v, policy, nil, true)
			if change.name == "original" {
				if err != nil || result.Acceptance != "pass" {
					t.Fatalf("original worker could not satisfy resume: %+v %v", result, err)
				}
				return
			}
			if spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "recipe differs") {
				t.Fatalf("resume trusted changed worker: %v", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("resume created duplicate migration")
				}
			}
			operation, err := e.Store.LatestOperation(ctx, "worker-run", p.Operations[0].ID)
			if err != nil || operation.State != "uncertain" {
				t.Fatalf("changed worker finalized original intent: %+v %v", operation, err)
			}
		})
	}
}

func mustDigest(t *testing.T, value any) string {
	t.Helper()
	digest, err := spec.Digest(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestAmbiguousJobCreationBlocksRecovery(t *testing.T) {
	e, client, policy, p, v, intent := workerFixture(t)
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		job.UID = "accepted-with-lost-response"
		if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, "test"); err != nil {
			t.Fatal(err)
		}
		return true, nil, errors.New("connection reset after server acceptance")
	})
	operation := p.Operations[0]
	if _, err := e.operation(context.Background(), p, "worker-run", operation, v, policy); spec.ExitCode(err) != 13 {
		t.Fatalf("ambiguous create recorded as definite failure: %v", err)
	}
	if err := e.Store.Complete(context.Background(), intent, "uncertain", nil); err != nil {
		t.Fatal(err)
	}
	if err := e.recoveryQuiescent(context.Background(), "worker-run"); spec.ExitCode(err) != 13 {
		t.Fatalf("recovery may race accepted worker: %v", err)
	}
}

func TestAcceptanceWorkerIsJournaledAndRecoveryWaitsForIt(t *testing.T) {
	e, client, _, p, v, _ := workerFixture(t)
	// The original migration is already durably complete; this test isolates
	// the independently mutating workflow acceptance worker.
	operations, _ := e.Store.Operations(context.Background(), "worker-run")
	if err := e.Store.Complete(context.Background(), operations[0], "complete", nil); err != nil {
		t.Fatal(err)
	}
	e.Site.Spec.Registry = "registry.internal/app"
	v.Index.Lock.Assets = []spec.LockedAsset{{ID: "runner", Type: "image", Digest: "sha256:" + strings.Repeat("a", 64)}}
	check := p.Checks[0]
	failPoll := true
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		intent, err := e.Store.LatestOperation(context.Background(), "worker-run", checkStepID(check.ID))
		if err != nil || journalKind(intent.Intent) != "check" {
			t.Fatal("acceptance worker started without durable intent")
		}
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = "acceptance-uid"
		return false, nil, nil
	})
	client.PrependReactor("get", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
		if failPoll {
			return true, nil, apierrors.NewTimeoutError("poll unavailable", 1)
		}
		return false, nil, nil
	})
	result := e.check(context.Background(), "worker-run", check, v)
	if result.Status != "blocked" {
		t.Fatalf("unobservable acceptance worker passed: %#v", result)
	}
	intent, err := e.Store.LatestOperation(context.Background(), "worker-run", checkStepID(check.ID))
	if err != nil || intent.State != "uncertain" {
		t.Fatalf("uncertain check not journaled: %#v %v", intent, err)
	}
	failPoll = false
	if err := e.recoveryQuiescent(context.Background(), "worker-run"); spec.ExitCode(err) != 13 {
		t.Fatalf("recovery raced live acceptance worker: %v", err)
	}
	job, _ := client.BatchV1().Jobs("test").Get(context.Background(), intent.ExternalID, metav1.GetOptions{})
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if _, err := client.BatchV1().Jobs("test").UpdateStatus(context.Background(), job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.recoveryQuiescent(context.Background(), "worker-run"); err != nil {
		t.Fatal(err)
	}
	if err := e.resumeCheck(context.Background(), p, intent); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	if result := e.check(context.Background(), "worker-run", check, v); result.Status != "pass" {
		t.Fatalf("recorded original check completion rejected: %#v", result)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			t.Fatal("completed acceptance check was rerun")
		}
	}
}

func TestPlanSourceVersionMustMatchBoundSnapshot(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	v.Index.Lock.Release.Spec.Transitions = append(v.Index.Lock.Release.Spec.Transitions, spec.Transition{ID: "other-source", FromRelease: "0.9.0", Operations: []string{"migration"}, Recovery: "repair"})
	p.SourceVersion = "0.9.0"
	p.TransitionID = "other-source"
	if err := e.checkPlan(context.Background(), p, v, policy, false); spec.ExitCode(err) != 11 {
		t.Fatalf("wrong source transition admitted: %v", err)
	}
	p.Snapshot.InstalledVersion = "0.9.0"
	if err := e.checkPlan(context.Background(), p, v, policy, false); spec.ExitCode(err) != 11 {
		t.Fatalf("edited embedded snapshot admitted: %v", err)
	}
}
