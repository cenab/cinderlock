package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func licensedRun(t *testing.T) (*Engine, *fake.Clientset, spec.TrustPolicy, spec.Plan, *bundle.Verified) {
	t.Helper()
	e, client, policy := fixture(t)
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"entitlement": {Name: "license", Key: "token"}}
	_, err := client.CoreV1().Secrets("test").Create(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "license", Namespace: "test", UID: "license-uid", ResourceVersion: "1"}, Data: map[string][]byte{"token": []byte("synthetic")}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, v := fixturePlan(t, e, policy)
	r := &v.Index.Lock.Release
	r.Spec.Assets = append(r.Spec.Assets, spec.Asset{ID: "renewal", Type: "file", Source: "renewal.txt"})
	r.Spec.License = &spec.LicenseRequirement{Mode: "offline", SecretRef: "entitlement", Check: "entitlement", MaxAgeSeconds: 3600, RenewalAsset: "renewal"}
	check := spec.Check{ID: "entitlement", Type: "job", Domain: "workflow", Required: true, Image: "runner", Command: []string{"/app/validate-entitlement"}, SecretRefs: []string{"entitlement"}, Script: fixtureScript("entitlement")}
	check.Script.Retry = "manual"
	r.Spec.Checks = append(r.Spec.Checks, check)
	r.Spec.Recovery[0].Checks = r.Spec.Checks
	r.Spec.Operations[0].Script.Retry, r.Spec.Operations[0].Idempotent = "manual", false
	p.Operations, p.Checks, p.Recovery = r.Spec.Operations, r.Spec.Checks, r.Spec.Recovery
	return e, client, policy, p, v
}

func storeResumePlan(t *testing.T, e *Engine, p spec.Plan, v *bundle.Verified, runID string) {
	t.Helper()
	plan, err := spec.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	site, err := spec.Canonical(e.Site)
	if err != nil {
		t.Fatal(err)
	}
	digest := mustDigest(t, p)
	if err := e.Store.CreateRun(context.Background(), state.Run{ID: runID, Application: p.Metadata.Application, Namespace: "test", TargetID: p.Snapshot.TargetID, PlanDigest: digest, BundleDigest: v.Digest, Plan: plan, Site: site}); err != nil {
		t.Fatal(err)
	}
	if err := e.clusterRecord(context.Background(), runID, digest, "acquiring", nil); err != nil {
		t.Fatal(err)
	}
}

func TestEntitlementPrerequisiteBeforeMutationAndNoBlindRepeat(t *testing.T) {
	for _, scenario := range []string{"pass", "failed", "uncertain", "missing-time", "stale", "future", "expired", "migration-failed", "stale-after-migration", "stale-after-check"} {
		t.Run(scenario, func(t *testing.T) {
			e, client, policy, p, v := licensedRun(t)
			if scenario == "expired" {
				v.Index.Lock.Release.Spec.License.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			}
			if scenario == "stale-after-check" {
				p.Checks = []spec.Check{p.Checks[1], p.Checks[0]}
				v.Index.Lock.Release.Spec.Checks = p.Checks
			}
			storeResumePlan(t, e, p, v, "license-run")
			created := []string{}
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				command := job.Spec.Template.Spec.Containers[0].Command[0]
				created = append(created, command)
				job.UID = types.UID("uid-" + job.Name)
				stamp := metav1.NewTime(time.Now().Add(-time.Second))
				job.Status.CompletionTime = &stamp
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				if command == "/app/validate-entitlement" {
					switch scenario {
					case "failed":
						job.Status.Conditions[0].Type = batchv1.JobFailed
					case "uncertain":
						if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job.DeepCopy(), "test"); err != nil {
							t.Fatal(err)
						}
						return true, nil, errors.New("lost create acknowledgement")
					case "missing-time":
						job.Status.CompletionTime = nil
					case "stale":
						job.Status.CompletionTime.Time = time.Now().Add(-2 * time.Hour)
					case "future":
						job.Status.CompletionTime.Time = time.Now().Add(time.Hour)
					}
				} else if job.Labels["cinderlock.dev/step"] == fingerprint("migration")[7:23] {
					if scenario == "migration-failed" {
						job.Status.Conditions[0].Type = batchv1.JobFailed
					}
				}
				step := job.Labels["cinderlock.dev/step"]
				if scenario == "stale-after-migration" && step == fingerprint("migration")[7:23] || scenario == "stale-after-check" && step == fingerprint(checkStepID("inference"))[7:23] {
					resource := batchv1.SchemeGroupVersion.WithResource("jobs")
					object, err := client.Tracker().Get(resource, "test", jobName("license-run", checkStepID("entitlement")))
					if err != nil {
						t.Fatal(err)
					}
					prior := object.(*batchv1.Job)
					prior.Status.CompletionTime.Time = time.Now().Add(-2 * time.Hour)
					if err := client.Tracker().Update(resource, prior, "test"); err != nil {
						t.Fatal(err)
					}
				}
				return false, nil, nil
			})
			result, err := e.Resume(context.Background(), "license-run", v, policy, nil, true)
			if scenario == "pass" {
				if err != nil || result.Acceptance != "pass" || strings.Join(created, ",") != "/app/validate-entitlement,/bin/true,/bin/true" {
					t.Fatalf("first authorized manual execution and cached entitlement check: acceptance=%s jobs=%v error=%v", result.Acceptance, created, err)
				}
				return
			}
			if err == nil || result.Acceptance == "pass" || result.Domains["workflow"] == "pass" {
				t.Fatalf("unsafe entitlement/mutation accepted: %#v %v", result, err)
			}
			want := "/app/validate-entitlement"
			if scenario == "expired" {
				want = ""
			}
			if scenario == "migration-failed" || scenario == "stale-after-migration" {
				want += ",/bin/true"
			}
			if scenario == "stale-after-check" {
				want += ",/bin/true,/bin/true"
			}
			seen := map[string]bool{}
			for _, check := range result.Checks {
				if seen[check.ID] {
					t.Fatalf("prerequisite has contradictory duplicate outcomes: %v", result.Checks)
				}
				seen[check.ID] = true
			}
			if strings.Join(created, ",") != want {
				t.Fatalf("application mutation crossed prerequisite: jobs=%v error=%v", created, err)
			}
			if _, retryErr := e.Resume(context.Background(), "license-run", v, policy, nil, true); retryErr == nil {
				t.Fatal("failed or stale prerequisite silently accepted on resume")
			}
			if strings.Join(created, ",") != want {
				t.Fatalf("resume started another worker: %v", created)
			}
		})
	}
}

func TestIntermediateReleaseIsActionableBlockerAndCannotBeForgedExecutable(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	r := &v.Index.Lock.Release
	r.Spec.Transitions[0].IntermediateReleases = []string{"1.5.0"}
	direct := r.Spec.Transitions[0]
	direct.ID, direct.FromRelease, direct.IntermediateReleases = "from-intermediate", "1.5.0", nil
	r.Spec.Transitions = append(r.Spec.Transitions, direct)
	plan, err := e.Plan(context.Background(), v, p.BundlePath, p.SitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable {
		t.Fatal("intermediate route executed as a direct transition")
	}
	found := false
	for _, finding := range plan.Findings {
		found = found || finding.Code == "INTERMEDIATE_RELEASE_REQUIRED" && strings.Contains(finding.Message, "1.5.0")
	}
	if !found {
		t.Fatalf("missing intermediate route instruction: %#v", plan.Findings)
	}
	if err := e.verifyRecipeBinding(p, v); spec.ExitCode(err) != 10 {
		t.Fatalf("a manufactured executable plan bypassed the intermediate route: %v", err)
	}
}

func TestOptionalJobCheckCannotReplaceRequiredAcceptance(t *testing.T) {
	for _, requiredFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "optional-fails", true: "required-fails"}[requiredFails], func(t *testing.T) {
			e, client, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			check := spec.Check{ID: "optional", Type: "job", Domain: "workflow", Image: "runner", Command: []string{"/app/optional"}, Script: fixtureScript("optional")}
			check.Script.Retry = "manual"
			v.Index.Lock.Release.Spec.Checks = append(v.Index.Lock.Release.Spec.Checks, check)
			p.Checks = v.Index.Lock.Release.Spec.Checks
			storeResumePlan(t, e, p, v, "optional-run")
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				job.UID = types.UID("uid-" + job.Name)
				condition := batchv1.JobComplete
				step := job.Labels["cinderlock.dev/step"]
				if !requiredFails && step == fingerprint(checkStepID("optional"))[7:23] || requiredFails && step == fingerprint(checkStepID("inference"))[7:23] {
					condition = batchv1.JobFailed
				}
				job.Status.Conditions = []batchv1.JobCondition{{Type: condition, Status: corev1.ConditionTrue}}
				return false, nil, nil
			})
			result, err := e.Resume(context.Background(), "optional-run", v, policy, nil, true)
			statuses := map[string]string{}
			for _, check := range result.Checks {
				statuses[check.ID] = check.Status
			}
			if requiredFails {
				if spec.ExitCode(err) != 15 || result.Acceptance == "pass" || statuses["inference"] != "fail" || statuses["optional"] != "pass" {
					t.Fatalf("optional pass replaced the required failure: acceptance=%s checks=%v error=%v", result.Acceptance, statuses, err)
				}
			} else if err != nil || result.Acceptance != "pass" || statuses["optional"] != "fail" || statuses["inference"] != "pass" {
				t.Fatalf("optional failure changed required acceptance: acceptance=%s checks=%v error=%v", result.Acceptance, statuses, err)
			}
		})
	}
}

func TestFailedManualSeedDoesNotRepeat(t *testing.T) {
	e, client, policy := fixture(t)
	e.Site.Spec.HelperImage = "runner"
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "seed")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "seed")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	p, v := fixturePlan(t, e, policy)
	op := &v.Index.Lock.Release.Spec.Operations[0]
	op.Type, op.Asset, op.PVC, op.MountPath, op.StorageBytes = "seed", "model", "model-v2", "/models", 1024
	op.Idempotent, op.Script.Retry = false, "manual"
	v.Index.Lock.Release.Spec.Assets = append(v.Index.Lock.Release.Spec.Assets, spec.Asset{ID: "model", Type: "model-tree", Source: "models"})
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "model", Type: "model-tree", Digest: spec.Hash([]byte("model")), Files: []spec.FileRecord{{Path: "weights.bin", Size: 1, Digest: spec.Hash([]byte("x"))}}})
	storeResumePlan(t, e, p, v, "manual-seed")
	intent, err := e.Store.Intent(context.Background(), "manual-seed", op.ID, *op, jobName("manual-seed", op.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Store.Complete(context.Background(), intent, "failed", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Resume(context.Background(), "manual-seed", v, policy, nil, true); spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "failed non-idempotent") {
		t.Fatalf("failed manual seed was allowed to repeat: %v", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			t.Fatal("failed manual seed created another worker")
		}
	}
}

func TestPrerequisiteWaitRevalidatesExecutionBoundary(t *testing.T) {
	for _, fault := range []struct {
		name string
		code int
	}{{"policy", 11}, {"site", 11}, {"secret", 11}, {"lease", 18}, {"approval", 16}} {
		t.Run(fault.name, func(t *testing.T) {
			e, client, policy, p, v := licensedRun(t)
			var approval *spec.Authorization
			if fault.name == "approval" {
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"approval"}}}
				policy.Spec.Epoch++
				admitFixturePolicy(t, e, policy)
				p.PolicyDigest, p.PolicyEpoch = mustDigest(t, policy), policy.Spec.Epoch
				approval = &spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: mustDigest(t, p), PlanKind: p.Kind, TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: p.PolicyEpoch, Actions: []string{"migrate"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: "approval"}
				if err := spec.SignAuthorization(approval, private, "customer"); err != nil {
					t.Fatal(err)
				}
			}
			storeResumePlan(t, e, p, v, "boundary-run")
			created := []string{}
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				command := job.Spec.Template.Spec.Containers[0].Command[0]
				created = append(created, command)
				job.UID = types.UID("uid-" + job.Name)
				stamp := metav1.NewTime(time.Now().Add(-time.Second))
				job.Status.CompletionTime = &stamp
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				if command != "/app/validate-entitlement" {
					return false, nil, nil
				}
				switch fault.name {
				case "policy":
					changed := policy
					changed.Spec.Epoch++
					body, err := spec.Canonical(changed)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(e.Site.Spec.TrustPolicy, body, 0600); err != nil {
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
					secret := object.(*corev1.Secret)
					secret.ResourceVersion = "2"
					if err := client.Tracker().Update(resource, secret, "test"); err != nil {
						t.Fatal(err)
					}
				case "lease":
					resource := coordv1.SchemeGroupVersion.WithResource("leases")
					object, err := client.Tracker().Get(resource, "test", "cinderlock-"+fingerprint("app")[7:27])
					if err != nil {
						t.Fatal(err)
					}
					lease := object.(*coordv1.Lease)
					holder := "replacement-holder"
					lease.Spec.HolderIdentity = &holder
					if err := client.Tracker().Update(resource, lease, "test"); err != nil {
						t.Fatal(err)
					}
				case "approval":
					approval.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				}
				return false, nil, nil
			})
			result, err := e.Resume(context.Background(), "boundary-run", v, policy, approval, true)
			if spec.ExitCode(err) != fault.code || result.Acceptance == "pass" || strings.Join(created, ",") != "/app/validate-entitlement" {
				t.Fatalf("mutation crossed changed %s boundary: acceptance=%s jobs=%v error=%v", fault.name, result.Acceptance, created, err)
			}
		})
	}
}
