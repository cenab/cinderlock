package engine

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func observationContract() *spec.ObservationContract {
	zero, one, latency, memory := int64(0), int64(1), int64(100), int64(4096)
	return &spec.ObservationContract{Version: 1, TestRevision: "cpu-fixture-1", AssertionRevision: "budgets-1", Profile: "cpu-test", SampleCount: 2, Sampling: map[string]int64{"seed": 42}, Nondeterminism: "Scheduling can vary latency even with a fixed seed.", Limitations: "Two synthetic CPU samples do not establish production capacity.", Metrics: []spec.MetricBound{
		{Name: "matched", Kind: "assertion", Unit: "count", Assertion: "The application found the required synthetic fixture.", Min: &one, Max: &one},
		{Name: "latency", Kind: "latency", Unit: "milliseconds", Assertion: "Each request completes within the application latency budget.", Min: &zero, Max: &latency},
		{Name: "memory", Kind: "resource", Unit: "bytes", Assertion: "Application-reported peak allocation stays within budget.", Min: &zero, Max: &memory},
	}}
}

func observationReport(t *testing.T, contract *spec.ObservationContract) spec.ObservationReport {
	t.Helper()
	one, latency, memory := int64(1), int64(50), int64(4000)
	return spec.ObservationReport{Version: 1, ContractDigest: mustDigest(t, contract), Profile: contract.Profile, Runtime: "python-3.14", Device: "cpu", Mode: "cpu", WarmCold: "warm", Concurrency: 1, Samples: []spec.ObservationSample{
		{Index: 1, Metrics: []spec.MetricValue{{Name: "matched", Unit: "count", Value: &one}, {Name: "latency", Unit: "milliseconds", Value: &latency}, {Name: "memory", Unit: "bytes", Value: &memory}}},
		{Index: 2, Metrics: []spec.MetricValue{{Name: "matched", Unit: "count", Value: &one}, {Name: "latency", Unit: "milliseconds", Value: &latency}, {Name: "memory", Unit: "bytes", Value: &memory}}},
	}}
}

func completedObservationWorker(t *testing.T, client *fake.Clientset) {
	t.Helper()
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		yes := true
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: "test", UID: types.UID("pod-" + job.Name), Labels: job.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{Name: "operation", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}}}
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, "test"); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
}

func TestCheckObservationsRejectsBudgetDespiteSuccessfulJob(t *testing.T) {
	for _, tc := range []struct {
		name           string
		sample, metric int
		value          int64
	}{{"assertion", 1, 0, 0}, {"latency", 1, 1, 101}, {"memory", 1, 2, 4097}, {"earlier_sample", 0, 1, 101}} {
		t.Run(tc.name, func(t *testing.T) {
			e, client, _, p, v, _ := workerFixture(t)
			completedObservationWorker(t, client)
			check := p.Checks[0]
			check.ObservationContract = observationContract()
			report := observationReport(t, check.ObservationContract)
			report.Samples[tc.sample].Metrics[tc.metric].Value = &tc.value
			output, err := spec.Canonical(report)
			if err != nil {
				t.Fatal(err)
			}
			e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
			result := e.check(context.Background(), "worker-run", check, v)
			if result.Status != "fail" || result.Observations == nil || result.Observations.Report == nil || *result.Observations.Report.Samples[tc.sample].Metrics[tc.metric].Value != tc.value {
				t.Fatalf("exit-zero Job with failing sample must retain failure and values, got %#v", result)
			}
		})
	}
}

func TestCheckObservationsRetainsRecordedResultAfterReopen(t *testing.T) {
	e, client, _, p, v, _ := workerFixture(t)
	completedObservationWorker(t, client)
	check := p.Checks[0]
	check.ObservationContract = observationContract()
	output, err := spec.Canonical(observationReport(t, check.ObservationContract))
	if err != nil {
		t.Fatal(err)
	}
	e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
	ctx := context.Background()
	result := e.check(ctx, "worker-run", check, v)
	if result.Status != "pass" || result.Observations == nil || result.Observations.Report == nil || *result.Observations.Report.Samples[1].Metrics[1].Value != 50 {
		t.Fatalf("valid samples not retained: %#v", result)
	}
	if err := e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	e.Store, err = state.Open(filepath.Join(e.StateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Store.Close() })
	intent, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
	var stored spec.CheckResult
	if err != nil || intent.State != "complete" || spec.Decode(intent.Evidence, &stored) != nil || mustDigest(t, stored) != mustDigest(t, result) {
		t.Fatalf("observations were not durably captured: %#v %v", intent, err)
	}
	e.PodLogReader = func(context.Context, string) ([]byte, error) {
		t.Fatal("finalized observations were reread")
		return nil, nil
	}
	client.ClearActions()
	if resumed := e.check(ctx, "worker-run", check, v); mustDigest(t, resumed) != mustDigest(t, result) {
		t.Fatalf("resume changed the original observation result: %#v", resumed)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			t.Fatal("completed observation Job was rerun")
		}
	}
}

func TestResumeCheckCollectsOriginalCompletedObservations(t *testing.T) {
	e, client, _, p, v, _ := workerFixture(t)
	completedObservationWorker(t, client)
	check := &p.Checks[0]
	check.ObservationContract = observationContract()
	ctx := context.Background()
	e.PodLogReader = func(context.Context, string) ([]byte, error) { return nil, errors.New("SYNTHETIC-SECRET") }
	result := e.check(ctx, "worker-run", *check, v)
	if result.Status != "blocked" || strings.Contains(result.Reason, "SYNTHETIC-SECRET") {
		t.Fatalf("transport uncertainty was not safely blocked: %#v", result)
	}
	intent, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
	var partial spec.CheckResult
	if err != nil || intent.State != "uncertain" || spec.Decode(intent.Evidence, &partial) != nil || partial.Observations == nil || partial.Observations.Source.PodUID == "" {
		t.Fatalf("source was not bound before log transport: %#v %v", intent, err)
	}
	report := observationReport(t, check.ObservationContract)
	overBudget := int64(101)
	report.Samples[1].Metrics[1].Value = &overBudget
	output, err := spec.Canonical(report)
	if err != nil {
		t.Fatal(err)
	}
	e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
	if err := e.resumeCheck(ctx, p, intent); err != nil {
		t.Fatal(err)
	}
	intent, err = e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
	var stored spec.CheckResult
	if err != nil || intent.State != "failed" || spec.Decode(intent.Evidence, &stored) != nil || stored.Status != "fail" || stored.Observations == nil || stored.Observations.Report == nil || *stored.Observations.Report.Samples[1].Metrics[1].Value != 101 {
		t.Fatalf("resume inferred success instead of retaining the failed budget: state=%s result=%#v error=%v", intent.State, stored, err)
	}
	e.PodLogReader = func(context.Context, string) ([]byte, error) {
		t.Fatal("failed observations were reread")
		return nil, nil
	}
	if resumed := e.check(ctx, "worker-run", *check, v); mustDigest(t, resumed) != mustDigest(t, stored) {
		t.Fatalf("known failed assertion changed on resume: %#v", resumed)
	}
}

func TestCheckObservationsBlocksMissingAndMalformedOutput(t *testing.T) {
	for _, output := range []string{"", "SYNTHETIC-SECRET", `{"SYNTHETIC-SECRET":1,"SYNTHETIC-SECRET":2}`, `{"version":1}`, strings.Repeat("x", spec.MaxObservationBytes+1)} {
		e, client, _, p, v, _ := workerFixture(t)
		completedObservationWorker(t, client)
		check := p.Checks[0]
		check.ObservationContract = observationContract()
		p.Checks[0] = check
		e.PodLogReader = func(context.Context, string) ([]byte, error) { return []byte(output), nil }
		ctx := context.Background()
		result := e.check(ctx, "worker-run", check, v)
		if result.Status != "blocked" || strings.Contains(result.Reason, "SYNTHETIC-SECRET") {
			t.Fatalf("invalid output did not safely block: %#v", result)
		}
		intent, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
		if err != nil || intent.State != "uncertain" || strings.Contains(string(intent.Evidence), "SYNTHETIC-SECRET") {
			t.Fatalf("invalid output leaked or was finalized: state=%s error=%v", intent.State, err)
		}
		if err := e.resumeCheck(ctx, p, intent); spec.ExitCode(err) != 13 {
			t.Fatalf("resume accepted missing/malformed output: %v", err)
		}
	}
}

func TestResumeObservationsRejectsSourceMutationBeforeReadingLogs(t *testing.T) {
	for _, mutation := range []string{"job_uid", "job_recipe", "pod_uid", "pod_owner", "pod_recipe", "missing_pod", "duplicate_pod"} {
		t.Run(mutation, func(t *testing.T) {
			e, client, _, p, v, _ := workerFixture(t)
			completedObservationWorker(t, client)
			check := &p.Checks[0]
			check.ObservationContract = observationContract()
			e.PodLogReader = func(context.Context, string) ([]byte, error) { return nil, errors.New("transport unavailable") }
			ctx := context.Background()
			result := e.check(ctx, "worker-run", *check, v)
			if result.Status != "blocked" || result.Observations == nil {
				t.Fatalf("source was not captured: %#v", result)
			}
			source := result.Observations.Source
			job, err := client.BatchV1().Jobs("test").Get(ctx, source.JobName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod, err := client.CoreV1().Pods("test").Get(ctx, source.PodName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "job_uid":
				job.UID = "replacement-job"
			case "job_recipe":
				job.Spec.Template.Spec.Containers[0].Command = []string{"/changed"}
			case "pod_uid":
				pod.UID = "replacement-pod"
			case "pod_owner":
				pod.OwnerReferences[0].UID = "another-job"
			case "pod_recipe":
				pod.Spec.Containers[0].Image = "different-image"
			case "duplicate_pod":
				duplicate := pod.DeepCopy()
				duplicate.Name, duplicate.UID = "second-pod", "second-uid"
				if _, err := client.CoreV1().Pods("test").Create(ctx, duplicate, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := client.BatchV1().Jobs("test").Update(ctx, job, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if mutation == "missing_pod" {
				if err := client.CoreV1().Pods("test").Delete(ctx, source.PodName, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			e.PodLogReader = func(context.Context, string) ([]byte, error) {
				t.Fatal("unbound source logs were read")
				return nil, nil
			}
			intent, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
			if err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if err := e.resumeCheck(ctx, p, intent); spec.ExitCode(err) != 13 {
				t.Fatalf("mutated observation source was accepted: %v", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("source uncertainty started a replacement Job")
				}
			}
		})
	}
}

func TestObservationPermissionsRequireLogsOnlyWhenOptedIn(t *testing.T) {
	for _, optedIn := range []bool{false, true} {
		e, client, policy := fixture(t)
		p, _ := fixturePlan(t, e, policy)
		if optedIn {
			p.Checks[0].ObservationContract = observationContract()
		}
		logRequested := false
		client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
			review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
			a := review.Spec.ResourceAttributes
			review.Status.Allowed = true
			if a.Resource == "pods" && a.Subresource == "log" {
				if a.Namespace != "test" || a.Verb != "get" {
					t.Fatalf("observation log permission escaped scope: %#v", a)
				}
				logRequested = true
				review.Status.Allowed, review.Status.Denied = false, true
			}
			return true, review, nil
		})
		e.addPermissionFindings(context.Background(), &p, nil)
		if logRequested != optedIn || p.Executable == optedIn {
			t.Fatalf("denied log permission must block only an observation plan: optedIn=%t requested=%t executable=%t", optedIn, logRequested, p.Executable)
		}
	}
}

func TestObservationContractIsBoundByCheckIntentAndPlan(t *testing.T) {
	for name, mutate := range map[string]func(*spec.ObservationContract){
		"test_revision":      func(c *spec.ObservationContract) { c.TestRevision = "changed" },
		"assertion_revision": func(c *spec.ObservationContract) { c.AssertionRevision = "changed" },
		"profile":            func(c *spec.ObservationContract) { c.Profile = "other" },
		"samples":            func(c *spec.ObservationContract) { c.SampleCount = 1 },
		"sampling":           func(c *spec.ObservationContract) { c.Sampling["seed"] = 43 },
		"nondeterminism":     func(c *spec.ObservationContract) { c.Nondeterminism = "Different scope." },
		"limitations":        func(c *spec.ObservationContract) { c.Limitations = "Different scope." },
		"assertion":          func(c *spec.ObservationContract) { c.Metrics[0].Assertion = "Different assertion." },
		"bound":              func(c *spec.ObservationContract) { *c.Metrics[1].Max = 101 },
	} {
		t.Run(name, func(t *testing.T) {
			e, _, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			check := p.Checks[0]
			check.ObservationContract = observationContract()
			v.Index.Lock.Release.Spec.Checks = []spec.Check{check}
			p.Checks = []spec.Check{check}
			if err := e.verifyRecipeBinding(p, v); err != nil {
				t.Fatal(err)
			}
			intent, err := spec.Canonical(checkIntent{Type: "check", Check: check})
			if err != nil {
				t.Fatal(err)
			}
			before := mustDigest(t, p)
			body, err := spec.Canonical(check.ObservationContract)
			if err != nil {
				t.Fatal(err)
			}
			var changed spec.ObservationContract
			if err := spec.Decode(body, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			p.Checks[0].ObservationContract = &changed
			if err := e.verifyRecipeBinding(p, v); spec.ExitCode(err) != 12 {
				t.Fatalf("changed observation declaration accepted by signed-recipe binding: %v", err)
			}
			if err := checkIntentMatches(intent, p.Checks[0]); spec.ExitCode(err) != 13 {
				t.Fatalf("changed observation declaration accepted by intent: %v", err)
			}
			if mustDigest(t, p) == before {
				t.Fatal("observation declaration was omitted from plan digest")
			}
		})
	}
}

func TestResumeRetainsObservedAcceptanceInRunResult(t *testing.T) {
	for _, budgetFails := range []bool{false, true} {
		e, client, policy := fixture(t)
		p, v := fixturePlan(t, e, policy)
		p.Checks[0].ObservationContract = observationContract()
		plan, err := spec.Canonical(p)
		if err != nil {
			t.Fatal(err)
		}
		site, err := spec.Canonical(e.Site)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		const runID = "numeric-resume"
		if err := e.Store.CreateRun(ctx, state.Run{ID: runID, Application: "app", Namespace: "test", TargetID: p.Snapshot.TargetID, PlanDigest: mustDigest(t, p), BundleDigest: v.Digest, Plan: plan, Site: site}); err != nil {
			t.Fatal(err)
		}
		completedObservationWorker(t, client)
		op := p.Operations[0]
		intent, err := e.Store.Intent(ctx, runID, op.ID, op, jobName(runID, op.ID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.operation(ctx, p, runID, op, v, policy); err != nil {
			t.Fatal(err)
		}
		if err := e.Store.Complete(ctx, intent, "complete", nil); err != nil {
			t.Fatal(err)
		}
		e.PodLogReader = func(context.Context, string) ([]byte, error) { return nil, errors.New("transport unavailable") }
		initial := e.check(ctx, runID, p.Checks[0], v)
		if initial.Status != "blocked" {
			t.Fatalf("expected interrupted observation collection: %#v", initial)
		}
		run := newResult(p, runID, mustDigest(t, p))
		run.State, run.Checks = "needs_reconciliation", []spec.CheckResult{initial}
		if err := e.Store.SetState(ctx, runID, run.State, true, run); err != nil {
			t.Fatal(err)
		}
		report := observationReport(t, p.Checks[0].ObservationContract)
		if budgetFails {
			over := int64(101)
			report.Samples[1].Metrics[1].Value = &over
		}
		output, err := spec.Canonical(report)
		if err != nil {
			t.Fatal(err)
		}
		e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
		client.ClearActions()
		resumed, err := e.Resume(ctx, runID, v, policy, nil, true)
		wantStatus, wantExit := "pass", 0
		if budgetFails {
			wantStatus, wantExit = "fail", 15
		}
		if spec.ExitCode(err) != wantExit || len(resumed.Checks) != 1 || resumed.Checks[0].Status != wantStatus || resumed.Checks[0].Observations == nil || resumed.Checks[0].Observations.Report == nil || *resumed.Checks[0].Observations.Report.Samples[1].Metrics[1].Value != *report.Samples[1].Metrics[1].Value {
			t.Fatalf("public resume lost observed acceptance: budgetFails=%t run=%#v error=%v", budgetFails, resumed, err)
		}
		for _, action := range client.Actions() {
			if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
				t.Fatal("public resume reran a completed worker")
			}
		}
	}
}

func TestObservationCaptureRejectsIdentityAndOutputChanges(t *testing.T) {
	for _, duringRead := range []bool{false, true} {
		e, client, _, p, v, _ := workerFixture(t)
		completedObservationWorker(t, client)
		check := &p.Checks[0]
		check.ObservationContract = observationContract()
		output, err := spec.Canonical(observationReport(t, check.ObservationContract))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		e.PodLogReader = func(ctx context.Context, name string) ([]byte, error) {
			intent, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
			var captured spec.CheckResult
			if err != nil || spec.Decode(intent.Evidence, &captured) != nil || captured.Observations == nil || captured.Observations.Source.PodName != name || captured.Observations.Source.PodUID == "" {
				t.Fatal("Pod identity was not durable before reading logs")
			}
			if !duringRead {
				return []byte(`{}`), nil
			}
			pod, err := client.CoreV1().Pods("test").Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod.UID = "replacement-during-log-read"
			if _, err := client.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			return output, nil
		}
		result := e.check(ctx, "worker-run", *check, v)
		if result.Status != "blocked" || result.Observations == nil || result.Observations.Report != nil {
			t.Fatalf("changing or malformed evidence was accepted: %#v", result)
		}
		if !duringRead {
			e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
			intent, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
			if err != nil {
				t.Fatal(err)
			}
			if err := e.resumeCheck(ctx, p, intent); spec.ExitCode(err) != 13 {
				t.Fatalf("valid replacement output overwrote captured malformed evidence: %v", err)
			}
		}
	}
}

func TestObservationProfileMismatchBlocksPlanning(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	p.Checks[0].ObservationContract = observationContract()
	p.Checks[0].ObservationContract.Profile = "other-profile"
	for _, finding := range e.ExecutionFindings(context.Background(), p, v) {
		if finding.Code == "OBSERVATION_PROFILE_MISMATCH" && finding.Severity == "blocker" {
			return
		}
	}
	t.Fatal("incompatible observation profile did not block planning")
}

func TestPrerequisiteRefreshPreservesObservedSamplesOnLaterFailure(t *testing.T) {
	e, client, policy, p, v := licensedRun(t)
	p.Checks[0].ObservationContract = observationContract()
	const runID = "observed-license-resume"
	storeResumePlan(t, e, p, v, runID)
	completedObservationWorker(t, client)
	output, err := spec.Canonical(observationReport(t, p.Checks[0].ObservationContract))
	if err != nil {
		t.Fatal(err)
	}
	e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
	initial := e.check(context.Background(), runID, p.Checks[0], v)
	if initial.Status != "pass" {
		t.Fatalf("original numeric check did not pass: %#v", initial)
	}
	client.PrependReactor("get", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		name := action.(ktesting.GetAction).GetName()
		object, err := client.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), "test", name)
		if err != nil {
			return true, nil, err
		}
		job := object.(*batchv1.Job).DeepCopy()
		if name == jobName(runID, checkStepID("entitlement")) {
			stamp := metav1.NewTime(time.Now().Add(-time.Second))
			job.Status.CompletionTime = &stamp
		}
		if name == jobName(runID, "migration") {
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
		}
		return true, job, nil
	})
	result, err := e.Resume(context.Background(), runID, v, policy, nil, true)
	if err == nil {
		t.Fatal("deliberately failed migration was accepted")
	}
	for _, check := range result.Checks {
		if check.ID == initial.ID && check.Observations != nil && check.Observations.Report != nil && len(check.Observations.Report.Samples) == 2 && *check.Observations.Report.Samples[1].Metrics[1].Value == 50 {
			return
		}
	}
	t.Fatalf("prerequisite refresh lost original samples before later migration failure: %#v, error=%v", result.Checks, err)
}

func TestResumeRetainsOptionalNumericFailureWithoutRepeatingWork(t *testing.T) {
	for _, fault := range []string{"original", "replaced-job", "running-pod"} {
		t.Run(fault, func(t *testing.T) {
			e, client, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			optional := p.Checks[0]
			optional.ID, optional.Required = "optional-numeric", false
			optional.Script = fixtureScript(optional.ID)
			optional.ObservationContract = observationContract()
			p.Checks = append(p.Checks, optional)
			v.Index.Lock.Release.Spec.Checks = p.Checks
			const runID = "optional-numeric-resume"
			storeResumePlan(t, e, p, v, runID)
			completedObservationWorker(t, client)
			ctx := context.Background()
			op := p.Operations[0]
			attempt, err := e.Store.Intent(ctx, runID, op.ID, op, jobName(runID, op.ID))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.operation(ctx, p, runID, op, v, policy); err != nil {
				t.Fatal(err)
			}
			if err := e.Store.Complete(ctx, attempt, "complete", nil); err != nil {
				t.Fatal(err)
			}
			required := e.check(ctx, runID, p.Checks[0], v)
			report := observationReport(t, optional.ObservationContract)
			outside := int64(101)
			report.Samples[1].Metrics[1].Value = &outside
			output, err := spec.Canonical(report)
			if err != nil {
				t.Fatal(err)
			}
			e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
			failed := e.check(ctx, runID, optional, v)
			if required.Status != "pass" || failed.Status != "fail" || failed.Observations == nil {
				t.Fatal("fixture did not complete required work and fail only the optional bounds", required, failed)
			}
			result := newResult(p, runID, mustDigest(t, p))
			result.State, result.Checks = "stopped", []spec.CheckResult{required, failed}
			if err := e.Store.SetState(ctx, runID, result.State, true, result); err != nil {
				t.Fatal(err)
			}
			if err := e.clusterRecord(ctx, runID, result.PlanDigest, result.State, result); err != nil {
				t.Fatal(err)
			}
			source := failed.Observations.Source
			if fault == "replaced-job" {
				job, err := client.BatchV1().Jobs("test").Get(ctx, source.JobName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				job.UID = "replacement"
				if _, err = client.BatchV1().Jobs("test").Update(ctx, job, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			} else if fault == "running-pod" {
				pod, err := client.CoreV1().Pods("test").Get(ctx, source.PodName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				pod.Status.Phase = corev1.PodRunning
				if _, err = client.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			e.PodLogReader = func(context.Context, string) ([]byte, error) {
				t.Fatal("resume reread finalized numeric output")
				return nil, nil
			}
			client.ClearActions()
			resumed, err := e.Resume(ctx, runID, v, policy, nil, true)
			if fault == "original" {
				if err != nil || resumed.Acceptance != "pass" || len(resumed.Checks) != 2 || resumed.Checks[1].Status != "fail" || resumed.Checks[1].Observations == nil || *resumed.Checks[1].Observations.Report.Samples[1].Metrics[1].Value != outside {
					t.Fatalf("recorded optional numeric failure prevented completion or lost samples: %#v, %v", resumed, err)
				}
			} else if spec.ExitCode(err) != 13 || resumed.Acceptance == "pass" {
				t.Fatalf("uncertain optional worker outcome was not preserved: fault=%s result=%#v error=%v", fault, resumed, err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("resume repeated a completed worker")
				}
			}
		})
	}
}
