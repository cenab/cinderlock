package engine

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestPrerequisiteGuardBelongsToNewWorkerStart(t *testing.T) {
	e, client, _, p, v := licensedRun(t)
	storeResumePlan(t, e, p, v, "prerequisite-boundary")
	sequence := []string{}
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		sequence = append(sequence, "create:"+job.Spec.Template.Spec.Containers[0].Command[0])
		job.UID = types.UID("uid-" + job.Name)
		stamp := metav1.NewTime(time.Now().Add(-time.Second))
		job.Status.CompletionTime = &stamp
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	guard := func() (spec.TargetSnapshot, error) {
		sequence = append(sequence, "guard")
		return spec.TargetSnapshot{}, nil
	}
	for _, first := range []bool{true, false} {
		sequence = []string{}
		results, err := e.prerequisiteChecks(context.Background(), p, v, "prerequisite-boundary", guard)
		if err != nil || len(results) != 1 || results[0].ID != "entitlement" || results[0].Status != "pass" {
			t.Fatalf("prerequisite evidence unavailable: %v %#v", err, results)
		}
		want := []string{}
		if first {
			want = []string{"guard", "create:/app/validate-entitlement"}
		}
		if !reflect.DeepEqual(sequence, want) {
			t.Fatalf("worker-start authority scope = %v, want %v; retained evidence must remain read-only", sequence, want)
		}
	}
}

func TestPrerequisiteRunKeepsOneGuardBeforeEachFollowingEffect(t *testing.T) {
	e, client, policy, p, v := licensedRun(t)
	storeResumePlan(t, e, p, v, "guarded-run")
	// Isolate execution work from the independently scheduled lease renewer.
	name, holder := "cinderlock-"+fingerprint("app")[7:27], "guarded-run-holder"
	if _, err := client.CoordinationV1().Leases("test").Create(context.Background(), &coordv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: coordv1.LeaseSpec{HolderIdentity: &holder}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	coord := &coordinator{e: e, name: name, holder: holder, runID: "guarded-run"}
	guards := 0
	client.PrependReactor("get", "leases", func(ktesting.Action) (bool, runtime.Object, error) {
		guards++
		return false, nil, nil
	})
	sequence := []string{}
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		step := job.Labels["cinderlock.dev/step"]
		want, name := 0, ""
		switch step {
		case fingerprint(checkStepID("entitlement"))[7:23]:
			want, name = 1, "entitlement"
		case fingerprint("migration")[7:23]:
			want, name = 1, "migration"
		case fingerprint(checkStepID("inference"))[7:23]:
			// The transition-to-verification lease check is additional to its worker guard.
			want, name = 2, "inference"
		default:
			t.Fatalf("unexpected worker %s", job.Name)
		}
		if guards != want {
			t.Errorf("%s followed %d coordination/authority checks, want %d", name, guards, want)
		}
		guards = 0
		sequence = append(sequence, name)
		job.UID = types.UID("uid-" + job.Name)
		stamp := metav1.NewTime(time.Now().Add(-time.Second))
		job.Status.CompletionTime = &stamp
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	result, err := e.execute(context.Background(), p, v, policy, nil, true, coord, newResult(p, "guarded-run", mustDigest(t, p)), true)
	if err != nil || result.Acceptance != "pass" || !reflect.DeepEqual(sequence, []string{"entitlement", "migration", "inference"}) {
		t.Fatalf("guarded execution changed its original workers/results: %v jobs=%v result=%#v", err, sequence, result)
	}
}

func TestEachNewPrerequisiteNeedsCurrentAuthority(t *testing.T) {
	e, client, _, p, v := licensedRun(t)
	e.Site.Spec.HelperImage = v.Index.Lock.Assets[0].Digest
	e.Site.Spec.AllowedHosts = []string{"registry.internal"}
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "endpoint-probe")
	endpoint := spec.Check{ID: "registry", Type: "endpoint", Domain: "readiness", Required: true, URL: "https://registry.internal/v2/", ExpectedStatus: 200, TimeoutSeconds: 1}
	p.Checks = append(p.Checks, endpoint)
	v.Index.Lock.Release.Spec.Checks = p.Checks
	storeResumePlan(t, e, p, v, "multiple-prerequisites")
	created := 0
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		created++
		job.UID = types.UID("uid-" + job.Name)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	guards := 0
	results, err := e.prerequisiteChecks(context.Background(), p, v, "multiple-prerequisites", func() (spec.TargetSnapshot, error) {
		guards++
		if guards == 2 {
			return spec.TargetSnapshot{}, spec.Err(16, "authority expired while the first prerequisite ran")
		}
		return spec.TargetSnapshot{}, nil
	})
	if spec.ExitCode(err) != 16 || guards != 2 || created != 1 || len(results) != 1 || results[0].ID != endpoint.ID || results[0].Status != "pass" {
		t.Fatalf("second prerequisite inherited old authority: guards=%d jobs=%d results=%#v error=%v", guards, created, results, err)
	}
	if _, err := e.Store.LatestOperation(context.Background(), "multiple-prerequisites", checkStepID("entitlement")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rejected second prerequisite gained an intent: %v", err)
	}
}

func TestRetainedPrerequisiteReadCannotBypassFollowingAuthority(t *testing.T) {
	for _, fault := range []string{"policy", "site", "secret", "lease", "job-uid", "job-recipe", "job-running", "job-read"} {
		t.Run(fault, func(t *testing.T) {
			e, client, policy, p, v := licensedRun(t)
			storeResumePlan(t, e, p, v, "retained-run")
			created, changed := []string{}, false
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				created = append(created, job.Spec.Template.Spec.Containers[0].Command[0])
				job.UID = types.UID("uid-" + job.Name)
				stamp := metav1.NewTime(time.Now().Add(-time.Second))
				job.Status.CompletionTime = &stamp
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				return false, nil, nil
			})
			client.PrependReactor("get", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				if changed || action.(ktesting.GetAction).GetName() != jobName("retained-run", checkStepID("entitlement")) {
					return false, nil, nil
				}
				migration, err := e.Store.LatestOperation(context.Background(), "retained-run", "migration")
				if err != nil || migration.State != "complete" {
					return false, nil, nil
				}
				changed = true
				switch fault {
				case "policy":
					policy.Spec.AllowedActions = nil
					if err := os.WriteFile(e.Site.Spec.TrustPolicy, mustCanonical(t, policy), 0600); err != nil {
						t.Fatal(err)
					}
				case "site":
					body, err := os.ReadFile(p.SitePath)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p.SitePath, append(body, '\n'), 0600); err != nil {
						t.Fatal(err)
					}
				case "secret":
					resource := corev1.SchemeGroupVersion.WithResource("secrets")
					object, err := client.Tracker().Get(resource, "test", "license")
					if err != nil {
						t.Fatal(err)
					}
					object.(*corev1.Secret).Data["token"] = []byte("changed")
					if err := client.Tracker().Update(resource, object, "test"); err != nil {
						t.Fatal(err)
					}
				case "lease":
					resource := coordv1.SchemeGroupVersion.WithResource("leases")
					object, err := client.Tracker().Get(resource, "test", "cinderlock-"+fingerprint("app")[7:27])
					if err != nil {
						t.Fatal(err)
					}
					holder := "other-holder"
					object.(*coordv1.Lease).Spec.HolderIdentity = &holder
					if err := client.Tracker().Update(resource, object, "test"); err != nil {
						t.Fatal(err)
					}
				case "job-read":
					return true, nil, errors.New("unavailable original worker")
				default:
					resource := batchv1.SchemeGroupVersion.WithResource("jobs")
					object, err := client.Tracker().Get(resource, "test", action.(ktesting.GetAction).GetName())
					if err != nil {
						t.Fatal(err)
					}
					job := object.(*batchv1.Job)
					switch fault {
					case "job-uid":
						job.UID = "replacement"
					case "job-recipe":
						job.Spec.Template.Spec.Containers[0].Command = []string{"/changed"}
					case "job-running":
						job.Status.Conditions = nil
					}
					if err := client.Tracker().Update(resource, job, "test"); err != nil {
						t.Fatal(err)
					}
				}
				return false, nil, nil
			})
			result, err := e.Resume(context.Background(), "retained-run", v, policy, nil, true)
			if !changed || err == nil || result.Acceptance == "pass" || !reflect.DeepEqual(created, []string{"/app/validate-entitlement", "/bin/true"}) {
				t.Fatalf("retained %s fault crossed into a following worker: changed=%v error=%v jobs=%v result=%#v", fault, changed, err, created, result)
			}
		})
	}
}

func TestFinalWorkflowLeaseLossBlocksAcceptanceWithRetainedPrerequisite(t *testing.T) {
	e, client, policy, p, v := licensedRun(t)
	p.Checks = []spec.Check{p.Checks[1], p.Checks[0]}
	v.Index.Lock.Release.Spec.Checks = p.Checks
	storeResumePlan(t, e, p, v, "final-lease")
	changed := false
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		stamp := metav1.NewTime(time.Now().Add(-time.Second))
		job.Status.CompletionTime = &stamp
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		if job.Labels["cinderlock.dev/step"] == fingerprint(checkStepID("inference"))[7:23] {
			resource := coordv1.SchemeGroupVersion.WithResource("leases")
			object, err := client.Tracker().Get(resource, "test", "cinderlock-"+fingerprint("app")[7:27])
			if err != nil {
				t.Fatal(err)
			}
			holder := "replacement-holder"
			object.(*coordv1.Lease).Spec.HolderIdentity = &holder
			if err := client.Tracker().Update(resource, object, "test"); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		return false, nil, nil
	})
	result, err := e.Resume(context.Background(), "final-lease", v, policy, nil, true)
	if !changed || spec.ExitCode(err) != 18 || result.Acceptance == "pass" {
		t.Fatalf("final workflow inherited the lost lease: changed=%v error=%v result=%#v", changed, err, result)
	}
	if len(result.Checks) != 2 || result.Checks[1].ID != "inference" || result.Checks[1].Status != "pass" {
		t.Fatalf("successful final workflow evidence lost: %#v", result.Checks)
	}
	floor, floorErr := e.Store.ReleaseFloor(context.Background(), p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
	if floorErr != nil || floor != 0 {
		t.Fatalf("lost lease advanced acceptance: floor=%d error=%v", floor, floorErr)
	}
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	body, err := spec.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
