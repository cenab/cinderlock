package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func assertJobBudget(t *testing.T, job *batchv1.Job, budget *spec.WorkerResources, timeout int64) {
	t.Helper()
	if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != timeout {
		t.Fatalf("worker deadline differs from %d: %v", timeout, job.Spec.ActiveDeadlineSeconds)
	}
	resources := job.Spec.Template.Spec.Containers[0].Resources
	temporary := int64(16 << 20)
	if budget == nil {
		if resources.Requests.Cpu().MilliValue() != 100 || resources.Requests.Memory().Value() != 64<<20 || resources.Limits.Memory().Value() != 256<<20 {
			t.Fatalf("fixed worker allocation changed: %#v", resources)
		}
		if _, ok := resources.Limits[corev1.ResourceCPU]; ok {
			t.Fatal("fixed worker acquired a CPU limit")
		}
		for _, values := range []corev1.ResourceList{resources.Requests, resources.Limits} {
			if _, ok := values[corev1.ResourceEphemeralStorage]; ok {
				t.Fatal("fixed worker acquired an ephemeral-storage allocation")
			}
		}
	} else {
		for _, values := range []corev1.ResourceList{resources.Requests, resources.Limits} {
			if len(values) != 3 || values.Cpu().MilliValue() != budget.CPUMillis || values.Memory().Value() != budget.MemoryBytes || values.StorageEphemeral().Value() != budget.EphemeralStorageBytes {
				t.Fatalf("worker allocation differs from declaration %+v: %#v", budget, resources)
			}
		}
		temporary = budget.TemporaryBytes
	}
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Name == "temporary" {
			if volume.EmptyDir == nil || volume.EmptyDir.Medium != "" || volume.EmptyDir.SizeLimit == nil || volume.EmptyDir.SizeLimit.Value() != temporary {
				t.Fatalf("worker temporary allocation differs from %d: %#v", temporary, volume)
			}
			return
		}
	}
	t.Fatal("worker lacks its bounded temporary volume")
}

func TestAuthoredJobsUseDeclaredBudget(t *testing.T) {
	for _, owner := range []string{"operation", "check"} {
		t.Run(owner, func(t *testing.T) {
			e, client, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			p.Operations[0].Script.Resources = &spec.WorkerResources{CPUMillis: 375, MemoryBytes: 128 << 20, EphemeralStorageBytes: 48 << 20, TemporaryBytes: 8 << 20}
			p.Operations[0].TimeoutSeconds = 17
			p.Checks[0].Script.Resources = &spec.WorkerResources{CPUMillis: 750, MemoryBytes: 96 << 20, EphemeralStorageBytes: 32 << 20, TemporaryBytes: 4 << 20}
			p.Checks[0].TimeoutSeconds = 23
			storeResumePlan(t, e, p, v, "worker-run")
			completeWorkers(client)
			ctx := context.Background()
			var name string
			var budget *spec.WorkerResources
			var timeout int64
			if owner == "operation" {
				op := p.Operations[0]
				if _, err := e.Store.Intent(ctx, "worker-run", op.ID, op, jobName("worker-run", op.ID)); err != nil {
					t.Fatal(err)
				}
				var err error
				name, err = e.operation(ctx, p, "worker-run", op, v, policy)
				if err != nil {
					t.Fatal(err)
				}
				budget, timeout = op.Script.Resources, op.TimeoutSeconds
				client.ClearActions()
				changed := op
				changed.TimeoutSeconds++
				if _, err := e.operation(ctx, p, "worker-run", changed, v, policy); spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "recipe") {
					t.Fatalf("changed recipe reused the original worker: %v", err)
				}
				for _, action := range client.Actions() {
					if action.GetVerb() == "create" {
						t.Fatal("changed recipe created another worker")
					}
				}
			} else {
				check := p.Checks[0]
				result := e.check(ctx, "worker-run", check, v, nil)
				if result.Status != "pass" {
					t.Fatalf("authored check failed: %+v", result)
				}
				name = strings.TrimPrefix(result.Evidence, "job/")
				budget, timeout = check.Script.Resources, check.TimeoutSeconds
			}
			job, err := client.BatchV1().Jobs("test").Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			assertJobBudget(t, job, budget, timeout)
		})
	}
}

func TestWorkerBudgetBlocksPlanApplyResumeAndDirectEffects(t *testing.T) {
	for _, owner := range []string{"operation", "seed", "check"} {
		for _, invalid := range []string{"missing-resources", "invalid-resources", "missing-timeout", "negative-timeout", "large-timeout"} {
			t.Run(owner+"/"+invalid, func(t *testing.T) {
				e, client, policy := fixture(t)
				p, v := fixturePlan(t, e, policy)
				op := &p.Operations[0]
				if owner == "seed" {
					op.Type, op.Asset, op.PVC, op.MountPath, op.StorageBytes = "seed", "model", "model-v2", "/models", 1024
					e.Site.Spec.HelperImage = "runner"
				}
				script, timeout := op.Script, &op.TimeoutSeconds
				code := "OPERATION_"
				if owner == "check" {
					script, timeout, code = p.Checks[0].Script, &p.Checks[0].TimeoutSeconds, "CHECK_"
				}
				want := "resources"
				switch invalid {
				case "missing-resources":
					script.Resources = nil
				case "invalid-resources":
					script.Resources.CPUMillis = 0
				case "missing-timeout":
					*timeout, want = 0, "timeout"
				case "negative-timeout":
					*timeout, want = -1, "timeout"
				case "large-timeout":
					*timeout, want = 86401, "timeout"
				}
				code += strings.ToUpper(want) + "_UNSUPPORTED"
				found := false
				for _, finding := range e.ExecutionFindings(context.Background(), p, v) {
					found = found || finding.Code == code && finding.Severity == "blocker"
				}
				if !found {
					t.Fatalf("missing profile finding %s", code)
				}
				storeResumePlan(t, e, p, v, "invalid-budget")
				client.ClearActions()
				ctx := context.Background()
				assertRejected := func(err error) {
					t.Helper()
					if spec.ExitCode(err) != 2 || !strings.Contains(err.Error(), want) {
						t.Fatalf("invalid worker %s admitted: %v", want, err)
					}
				}
				_, err := e.Plan(ctx, v, p.BundlePath, p.SitePath, policy)
				assertRejected(err)
				_, err = e.Apply(ctx, p, v, policy, nil, true)
				assertRejected(err)
				_, err = e.Resume(ctx, "invalid-budget", v, policy, nil, true)
				assertRejected(err)
				if owner == "check" {
					result := e.check(ctx, "invalid-budget", p.Checks[0], v, nil)
					if result.Status != "blocked" || !strings.Contains(result.Reason, want) {
						t.Fatalf("invalid check reached execution: %+v", result)
					}
				} else {
					_, err := e.operation(ctx, p, "invalid-budget", *op, v, policy)
					assertRejected(err)
				}
				if len(client.Actions()) != 0 {
					t.Fatalf("invalid worker reached Kubernetes: %#v", client.Actions())
				}
				operations, err := e.Store.Operations(ctx, "invalid-budget")
				if err != nil || len(operations) != 0 {
					t.Fatalf("invalid worker persisted an intent: %+v %v", operations, err)
				}
			})
		}
	}
}

func TestJobOptionsRejectInvalidBudgetBeforeEffects(t *testing.T) {
	e, client, _, _, _, _ := workerFixture(t)
	client.ClearActions()
	_, err := e.executeJobWithOptions(context.Background(), "worker-run", "invalid", "internal/runner", []string{"/bin/true"}, nil, nil, "", "", 1, &jobOptions{Resources: &spec.WorkerResources{CPUMillis: -1}})
	if spec.ExitCode(err) != 2 || !strings.Contains(err.Error(), "resources") || len(client.Actions()) != 0 {
		t.Fatalf("invalid override reached Job creation: %v %v", err, client.Actions())
	}
}

func TestChangedOperationBudgetIntentCannotSatisfyResume(t *testing.T) {
	for _, field := range []string{"resources", "timeout"} {
		t.Run(field, func(t *testing.T) {
			e, client, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			storeResumePlan(t, e, p, v, "intent-budget")
			var changed spec.Operation
			body, err := spec.Canonical(p.Operations[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := spec.Decode(body, &changed); err != nil {
				t.Fatal(err)
			}
			if field == "resources" {
				changed.Script.Resources.CPUMillis++
			} else {
				changed.TimeoutSeconds++
			}
			ctx := context.Background()
			intent, err := e.Store.Intent(ctx, "intent-budget", changed.ID, changed, jobName("intent-budget", changed.ID))
			if err != nil {
				t.Fatal(err)
			}
			completeWorkers(client)
			if _, err := e.operation(ctx, p, "intent-budget", changed, v, policy); err != nil {
				t.Fatal(err)
			}
			if err := e.Store.Complete(ctx, intent, "uncertain", nil); err != nil {
				t.Fatal(err)
			}
			if err := e.clusterRecord(ctx, "intent-budget", mustDigest(t, p), "uncertain", intent); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if _, err := e.Resume(ctx, "intent-budget", v, policy, nil, true); spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "intent differs from the signed plan") {
				t.Fatalf("changed intent satisfied original plan: %v", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("changed operation intent started another worker")
				}
			}
		})
	}
}

func TestChangedCheckBudgetIntentCannotSatisfyResume(t *testing.T) {
	for _, field := range []string{"resources", "timeout"} {
		t.Run(field, func(t *testing.T) {
			e, client, _, p, v, _ := workerFixture(t)
			completeWorkers(client)
			ctx := context.Background()
			check := p.Checks[0]
			if result := e.check(ctx, "worker-run", check, v, nil); result.Status != "pass" {
				t.Fatalf("original check failed: %+v", result)
			}
			attempt, err := e.Store.LatestOperation(ctx, "worker-run", checkStepID(check.ID))
			if err != nil {
				t.Fatal(err)
			}
			var changed checkIntent
			if err := spec.Decode(attempt.Intent, &changed); err != nil {
				t.Fatal(err)
			}
			if field == "resources" {
				changed.Check.Script.Resources.MemoryBytes++
			} else {
				changed.Check.TimeoutSeconds++
			}
			attempt.Intent, err = json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if err := e.resumeCheck(ctx, p, attempt); spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "intent differs from signed plan check") {
				t.Fatalf("changed check intent satisfied original check: %v", err)
			}
			if result := e.check(ctx, "worker-run", changed.Check, v, nil); result.Status != "blocked" || !strings.Contains(result.Reason, "intent differs") {
				t.Fatalf("changed check reused original completion: %+v", result)
			}
			if len(client.Actions()) != 0 {
				t.Fatal("changed check intent reached Kubernetes")
			}
		})
	}
}

func TestFixedJobAndNodeQualifiedGPUProbeKeepBudgets(t *testing.T) {
	for _, probe := range []bool{false, true} {
		e, client, _, p, _, _ := workerFixture(t)
		completeWorkers(client)
		ctx := context.Background()
		var options *jobOptions
		timeout := int64(0)
		if probe {
			options = &jobOptions{NodeName: "qualified-node", NodeUID: "qualified-uid", GPUCount: 2, BundleDigest: p.BundleDigest, Profile: "nvidia"}
			timeout = 120
		}
		name, err := e.executeJobWithOptions(ctx, "worker-run", p.Operations[0].ID, "internal/helper", []string{"/fixed-helper"}, nil, nil, "", "", timeout, options)
		if err != nil {
			t.Fatal(err)
		}
		job, err := client.BatchV1().Jobs("test").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !probe {
			timeout = 300
		}
		assertJobBudget(t, job, nil, timeout)
		if probe {
			resources := job.Spec.Template.Spec.Containers[0].Resources
			for _, values := range []corev1.ResourceList{resources.Requests, resources.Limits} {
				gpu := values[corev1.ResourceName("nvidia.com/gpu")]
				if gpu.Value() != 2 {
					t.Fatalf("qualified probe lost its full-device allocation: %#v", resources)
				}
			}
			terms := job.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
			if len(terms) != 1 || len(terms[0].MatchFields) != 1 || terms[0].MatchFields[0].Key != "metadata.name" || strings.Join(terms[0].MatchFields[0].Values, ",") != "qualified-node" || job.Annotations["cinderlock.dev/node-uid"] != "qualified-uid" {
				t.Fatalf("qualified probe node identity changed: %+v", job)
			}
		}
	}
}

func TestFixedHTTPCheckKeepsBudgetAndOptionalTimeout(t *testing.T) {
	e, client, _, p, v, _ := workerFixture(t)
	completeWorkers(client)
	e.Site.Spec.AllowedHosts = []string{"api.internal"}
	check := p.Checks[0]
	check.Type, check.Script, check.Command, check.TimeoutSeconds = "http", nil, nil, 0
	check.URL, check.ExpectedStatus = "http://api.internal/ready", 200
	result := e.check(context.Background(), "worker-run", check, v, nil)
	if result.Status != "pass" {
		t.Fatalf("fixed HTTP check failed: %+v", result)
	}
	job, err := client.BatchV1().Jobs("test").Get(context.Background(), strings.TrimPrefix(result.Evidence, "job/"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertJobBudget(t, job, nil, 300)
}
