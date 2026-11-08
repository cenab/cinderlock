package engine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestDeclaredFixtureUsesSelectedDedicatedNativeSeed(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	digest := "sha256:" + strings.Repeat("d", 64)
	e.Site.Spec.HelperImage = digest
	p.Operations = []spec.Operation{{ID: "seed-fixture", Type: "seed", Asset: "documents", PVC: "documents-v2", MountPath: "/documents", StorageBytes: 1024}}
	p.Checks[0].Fixtures = []string{"documents"}
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "helper", Type: "image", Digest: digest}, spec.LockedAsset{ID: "documents", Type: "file-tree", Digest: spec.Hash([]byte("documents")), Files: []spec.FileRecord{{Path: "document.txt", Digest: spec.Hash([]byte("test")), Size: 4}}})
	for _, finding := range e.ExecutionFindings(context.Background(), p, v) {
		if finding.Severity == "blocker" && strings.Contains(finding.Code, "FIXTURE") {
			t.Fatalf("dedicated selected native fixture remains blocked: %#v", finding)
		}
	}
}

func fixtureAcceptanceRun(t *testing.T, kind string) (*Engine, *fake.Clientset, spec.Plan, *bundle.Verified, string) {
	t.Helper()
	ctx := context.Background()
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	p.Kind = kind
	content := []byte("fixture document")
	files := []spec.FileRecord{{Path: "document.txt", Digest: spec.Hash(content), Size: int64(len(content))}}
	cache := t.TempDir()
	blob, err := bundle.BlobPath(cache, files[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(blob), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, content, 0600); err != nil {
		t.Fatal(err)
	}
	v.Root = cache
	helper := "sha256:" + strings.Repeat("d", 64)
	e.Site.Spec.HelperImage = helper
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "helper", Type: "image", Digest: helper}, spec.LockedAsset{ID: "documents", Type: "file-tree", Digest: spec.Hash([]byte("documents-tree")), Files: files})
	op := spec.Operation{ID: "seed-documents", Type: "seed", Asset: "documents", PVC: "fixtures-v2", MountPath: "/documents", ModelSubPath: "artifact", StorageBytes: 1024, TimeoutSeconds: 2}
	p.Operations = []spec.Operation{op}
	p.Checks[0].Fixtures = []string{"documents"}
	p.Checks[0].TimeoutSeconds = 2
	p.Checks[0].Command = []string{"/app/check", "/cinderlock-fixtures/documents/document.txt"}
	p.Findings = append(p.Findings, spec.Finding{Code: "ADMISSION_SCOPE", Severity: "info", Message: "point-in-time admission scope"})
	v.Index.Lock.Release.Spec.Operations = p.Operations
	v.Index.Lock.Release.Spec.Checks = p.Checks
	body, _ := spec.Canonical(p)
	site, _ := spec.Canonical(e.Site)
	if err := e.Store.CreateRun(ctx, state.Run{ID: "fixture-run", Application: "app", TargetID: p.Snapshot.TargetID, Namespace: "test", PlanDigest: mustDigest(t, p), BundleDigest: v.Digest, Plan: body, Site: site}); err != nil {
		t.Fatal(err)
	}
	intent, err := e.Store.Intent(ctx, "fixture-run", op.ID, op, "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	client.PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		cm := a.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap)
		cm.UID = types.UID("uid-" + cm.Name)
		return false, nil, nil
	})
	client.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
		job := a.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		if job.Spec.Template.Spec.Containers[0].Command[0] == "/usr/local/bin/cinderlock" {
			assertJobBudget(t, job, nil, 2)
		} else {
			assertJobBudget(t, job, p.Checks[0].Script.Resources, 2)
		}
		job.UID = types.UID("uid-" + job.Name)
		if job.Spec.Template.Spec.Containers[0].Stdin {
			yes := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: "test", UID: types.UID("uid-" + job.Name + "-pod"), Labels: job.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "operation", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, "test"); err != nil {
				t.Fatal(err)
			}
		} else {
			condition := batchv1.JobComplete
			command := job.Spec.Template.Spec.Containers[0].Command
			if len(command) > 2 && command[2] == "verify-model" {
				if err := modelstage.Verify(filepath.Join(root, "artifact"), files); err != nil {
					condition = batchv1.JobFailed
				}
			}
			job.Status.Conditions = []batchv1.JobCondition{{Type: condition, Status: corev1.ConditionTrue}}
		}
		return false, nil, nil
	})
	e.ModelAttach = func(ctx context.Context, podName string, input io.Reader, stdout, stderr io.Writer) error {
		if err := modelstage.Receive(ctx, root, "artifact", files, input); err != nil {
			return err
		}
		pod, err := client.CoreV1().Pods("test").Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		pod.Status.Phase = corev1.PodSucceeded
		pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
		if _, err = client.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
			return err
		}
		job, err := client.BatchV1().Jobs("test").Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		_, err = client.BatchV1().Jobs("test").UpdateStatus(ctx, job, metav1.UpdateOptions{})
		return err
	}
	if _, err := e.seedPVC(ctx, "fixture-run", op, v); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.Complete(ctx, intent, "complete", map[string]string{"state": "verified"}); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	return e, client, p, v, root
}

func TestExecutionRechecksPreserveAdmittedFixturePlanFindings(t *testing.T) {
	e, _, p, v, _ := fixtureAcceptanceRun(t, "Plan")
	e.Site.Spec.AllowedActions = []string{"seed", "job"}
	policy := spec.TrustPolicy{Spec: spec.TrustSpec{AllowedActions: []string{"seed", "job"}}}
	if err := e.checkExecutionProfile(context.Background(), p, v, policy); err != nil {
		t.Fatalf("completed fixture lost its admitted plan identity at a safe boundary: %v", err)
	}
}

func TestAcceptanceFixturesAreVerifiedMountedReadOnlyAndJournaled(t *testing.T) {
	for _, kind := range []string{"Plan", "RecoveryPlan"} {
		t.Run(kind, func(t *testing.T) {
			e, client, p, v, _ := fixtureAcceptanceRun(t, kind)
			ctx := context.Background()
			check := p.Checks[0]
			result := e.check(ctx, "fixture-run", check, v, nil)
			if result.Status != "pass" {
				t.Fatalf("declared fixture did not reach acceptance: %#v", result)
			}
			intent, err := e.Store.LatestOperation(ctx, "fixture-run", checkStepID(check.ID))
			if err != nil || intent.State != "complete" {
				t.Fatalf("acceptance outcome missing: %#v %v", intent, err)
			}
			bindings, err := fixtureIntentBindings(intent.Intent)
			if err != nil || len(bindings) != 1 || bindings[0].PVCUID != "uid-fixtures-v2" || bindings[0].AssetID != "documents" || bindings[0].SubPath != "artifact" {
				t.Fatalf("exact fixture provenance was not persisted: %#v %v", bindings, err)
			}
			worker, err := e.operationWorker(ctx, "fixture-run", intent.StepID, intent.Attempt, intent.StepID)
			if err != nil {
				t.Fatal(err)
			}
			job, err := client.BatchV1().Jobs("test").Get(ctx, worker.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			container := job.Spec.Template.Spec.Containers[0]
			mounted := false
			for _, mount := range container.VolumeMounts {
				if mount.MountPath == "/cinderlock-fixtures/documents" {
					mounted = mount.ReadOnly && mount.SubPath == "artifact"
					for _, volume := range job.Spec.Template.Spec.Volumes {
						if volume.Name == mount.Name {
							mounted = mounted && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == "fixtures-v2" && volume.PersistentVolumeClaim.ReadOnly
						}
					}
				}
			}
			if !mounted {
				t.Fatalf("acceptance ignored or exposed writable fixture: %#v", container.VolumeMounts)
			}
			if err := e.validateCheckFixtures(ctx, "fixture-run", p, check, bindings, true); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if repeat := e.check(ctx, "fixture-run", check, v, nil); repeat.Status != "pass" {
				t.Fatalf("recorded acceptance rejected: %#v", repeat)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("accepted fixture workflow was duplicated")
				}
			}
		})
	}
}

func TestFixtureAcceptanceRechecksActualBytesBeforeRunningWorkflow(t *testing.T) {
	e, client, p, v, root := fixtureAcceptanceRun(t, "Plan")
	if err := os.WriteFile(filepath.Join(root, "artifact/document.txt"), []byte("corrupted bytes!"), 0600); err != nil {
		t.Fatal(err)
	}
	result := e.check(context.Background(), "fixture-run", p.Checks[0], v, nil)
	if result.Status != "fail" {
		t.Fatalf("changed fixture bytes reached application acceptance: %#v", result)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
			if job.Name == jobName("fixture-run", checkStepID(p.Checks[0].ID)) {
				t.Fatal("application workflow started after fixture verification failed")
			}
		}
	}
	intent, err := e.Store.LatestOperation(context.Background(), "fixture-run", checkStepID(p.Checks[0].ID))
	if err != nil || intent.State != "failed" {
		t.Fatalf("failed fixture verifier was not durably recorded: %#v %v", intent, err)
	}
	if err := e.recoveryQuiescent(context.Background(), "fixture-run"); err != nil {
		t.Fatalf("known terminal readonly verifier prevents explicit recovery: %v", err)
	}
}

func TestFixtureIdentityAndSharingFailBeforeNewWorkers(t *testing.T) {
	for _, scenario := range []string{"replacement-pvc", "replacement-manifest", "replacement-verifier", "writable-pod", "unknown-readonly-pod", "different-bundle"} {
		t.Run(scenario, func(t *testing.T) {
			e, client, p, v, _ := fixtureAcceptanceRun(t, "Plan")
			ctx := context.Background()
			switch scenario {
			case "replacement-pvc":
				claim, _ := client.CoreV1().PersistentVolumeClaims("test").Get(ctx, "fixtures-v2", metav1.GetOptions{})
				claim.UID = "replacement-with-copied-annotations"
				if _, err := client.CoreV1().PersistentVolumeClaims("test").Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "replacement-manifest":
				cm, _ := client.CoreV1().ConfigMaps("test").Get(ctx, jobName("fixture-run", "manifest-seed-documents"), metav1.GetOptions{})
				cm.UID = "replacement-with-identical-data"
				if _, err := client.CoreV1().ConfigMaps("test").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				// The verifier still mounts this name, so replacing an immutable
				// manifest cannot inherit the original verifier's result.
				job, _ := client.BatchV1().Jobs("test").Get(ctx, jobName("fixture-run", "verify-model-seed-documents/attempt/1"), metav1.GetOptions{})
				if job == nil {
					t.Fatal("original verifier missing")
				}
			case "replacement-verifier":
				job, err := client.BatchV1().Jobs("test").Get(ctx, jobName("fixture-run", "verify-model-seed-documents/attempt/1"), metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				job.UID = "replacement-worker"
				if _, err := client.BatchV1().Jobs("test").Update(ctx, job, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "writable-pod", "unknown-readonly-pod":
				ro := scenario == "unknown-readonly-pod"
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "test", UID: "unrelated"}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "fixtures-v2", ReadOnly: ro}}}}, Containers: []corev1.Container{{Name: "other", Image: "unknown", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: ro}}}}}}
				if _, err := client.CoreV1().Pods("test").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "different-bundle":
				v.Digest = spec.Hash([]byte("other bundle"))
			}
			client.ClearActions()
			result := e.check(ctx, "fixture-run", p.Checks[0], v, nil)
			if result.Status != "blocked" {
				t.Fatalf("untrusted fixture passed: %#v", result)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatalf("identity failure was discovered after a new write: %s %s", action.GetVerb(), action.GetResource().Resource)
				}
			}
		})
	}
}

func TestFixtureWorkerCannotAcceptChangedVolumeOrResumeWithoutFreshVerification(t *testing.T) {
	for _, scenario := range []string{"resume-original", "resume-replacement", "missing-fresh-verifier"} {
		t.Run(scenario, func(t *testing.T) {
			e, client, p, v, _ := fixtureAcceptanceRun(t, "Plan")
			ctx := context.Background()
			check := p.Checks[0]
			lostPoll := true
			client.PrependReactor("get", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				if lostPoll && action.(ktesting.GetAction).GetName() == jobName("fixture-run", checkStepID(check.ID)) {
					return true, nil, apierrors.NewTimeoutError("response lost", 1)
				}
				return false, nil, nil
			})
			if result := e.check(ctx, "fixture-run", check, v, nil); result.Status != "blocked" {
				t.Fatalf("lost application response accepted: %#v", result)
			}
			lostPoll = false
			intent, err := e.Store.LatestOperation(ctx, "fixture-run", checkStepID(check.ID))
			if err != nil || intent.State != "uncertain" {
				t.Fatalf("lost response was finalized: %#v %v", intent, err)
			}
			switch scenario {
			case "resume-replacement":
				claim, _ := client.CoreV1().PersistentVolumeClaims("test").Get(ctx, "fixtures-v2", metav1.GetOptions{})
				claim.UID = "replacement"
				if _, err := client.CoreV1().PersistentVolumeClaims("test").Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "missing-fresh-verifier":
				if err := client.BatchV1().Jobs("test").Delete(ctx, jobName("fixture-run", fixtureVerifierRole(check.ID, "documents")), metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			client.ClearActions()
			err = e.resumeCheck(ctx, p, intent)
			if scenario == "resume-original" {
				if err != nil {
					t.Fatalf("original verified worker could not resume: %v", err)
				}
			} else if spec.ExitCode(err) != 13 {
				t.Fatalf("changed or incomplete fixture evidence accepted: %v", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" {
					t.Fatal("fixture reconciliation created a replacement worker")
				}
			}
		})
	}
}

func TestLostOrRunningFixtureVerifierNeverImpliesMainNotStarted(t *testing.T) {
	e, client, p, v, _ := fixtureAcceptanceRun(t, "Plan")
	ctx := context.Background()
	check := p.Checks[0]
	name := jobName("fixture-run", fixtureVerifierRole(check.ID, "documents"))
	lost := true
	client.PrependReactor("get", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		if lost && action.(ktesting.GetAction).GetName() == name {
			return true, nil, apierrors.NewTimeoutError("unobservable helper", 1)
		}
		return false, nil, nil
	})
	if result := e.check(ctx, "fixture-run", check, v, nil); result.Status != "blocked" {
		t.Fatalf("unobserved fixture helper accepted: %#v", result)
	}
	if err := e.recoveryQuiescent(ctx, "fixture-run"); spec.ExitCode(err) != 13 {
		t.Fatalf("recovery inferred missing application worker termination: %v", err)
	}
	lost = false
	job, err := client.BatchV1().Jobs("test").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	job.Status.Conditions = nil
	if _, err = client.BatchV1().Jobs("test").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.recoveryQuiescent(ctx, "fixture-run"); spec.ExitCode(err) != 13 {
		t.Fatalf("recovery raced running helper: %v", err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
	if _, err = client.BatchV1().Jobs("test").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.recoveryQuiescent(ctx, "fixture-run"); spec.ExitCode(err) != 13 {
		t.Fatalf("missing durable phase marker was inferred from terminal helper: %v", err)
	}
}

func TestFixturePreflightRejectsAmbiguousAndSharedSources(t *testing.T) {
	for _, scenario := range []string{"missing-seed", "duplicate-seed", "carrier-seed", "shared-operation", "duplicate-fixture", "image-fixture", "http-fixture", "chart-sharing", "existing-pod"} {
		t.Run(scenario, func(t *testing.T) {
			e, client, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			helper := "sha256:" + strings.Repeat("d", 64)
			e.Site.Spec.HelperImage = helper
			seed := spec.Operation{ID: "seed-documents", Type: "seed", Asset: "documents", PVC: "fixture-v2", MountPath: "/documents", StorageBytes: 1024}
			p.Operations = []spec.Operation{seed}
			p.Checks[0].Fixtures = []string{"documents"}
			v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "helper", Type: "image", Digest: helper}, spec.LockedAsset{ID: "documents", Type: "file-tree", Digest: spec.Hash([]byte("tree")), Files: []spec.FileRecord{{Path: "document.txt", Digest: spec.Hash([]byte("x")), Size: 1}}})
			switch scenario {
			case "missing-seed":
				p.Operations = nil
			case "duplicate-seed":
				other := seed
				other.ID = "seed-again"
				other.PVC = "other"
				p.Operations = append(p.Operations, other)
			case "carrier-seed":
				p.Operations[0].Image = "runner"
				p.Operations[0].Command = []string{"/vendor/stage"}
			case "shared-operation":
				p.Operations = append(p.Operations, spec.Operation{ID: "mutate-fixture", Type: "job", Image: "runner", Command: []string{"/app/write"}, PVC: seed.PVC, MountPath: "/data", Idempotent: true, Script: fixtureScript(p.Checks[0].ID), TimeoutSeconds: 1})
			case "duplicate-fixture":
				p.Checks[0].Fixtures = append(p.Checks[0].Fixtures, "documents")
			case "image-fixture":
				v.Index.Lock.Assets[len(v.Index.Lock.Assets)-1].Type = "image"
			case "http-fixture":
				p.Checks[0].Type = "http"
			case "chart-sharing":
				p.Operations = append(p.Operations, spec.Operation{ID: "deploy", Type: "helm"})
				chart := chartFixture(t, e)
				v.Root = chart.Root
				v.Index.Lock.Assets = append(v.Index.Lock.Assets, chart.Index.Lock.Assets...)
				previous := e.HelmRunner
				e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
					if args[0] == "template" {
						return []byte("apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: fixture-v2\n"), nil
					}
					return previous(ctx, args...)
				}
			case "existing-pod":
				_, err := client.CoreV1().Pods("test").Create(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "test"}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: seed.PVC}}}}}}, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}
			client.ClearActions()
			blocked := false
			for _, finding := range e.ExecutionFindings(context.Background(), p, v) {
				if finding.Severity == "blocker" && strings.Contains(finding.Code, "FIXTURE") {
					blocked = true
				}
			}
			if !blocked {
				t.Fatal("unsupported fixture source was admitted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("fixture planning performed a mutation")
				}
			}
		})
	}
	object := map[string]any{"kind": "Deployment", "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"volumes": []any{map[string]any{"persistentVolumeClaim": map[string]any{"claimName": "fixture-v2"}}}}}}}
	if !referencesFixture(object, "fixture-v2") || referencesFixture(object, "separate") {
		t.Fatal("chart fixture PVC reference was not distinguished")
	}
}

func TestSignedSeedManifestRejectsReplacementPVCWithCopiedAnnotations(t *testing.T) {
	e, client, policy := fixture(t)
	_, v := fixturePlan(t, e, policy)
	digest := spec.Hash([]byte("fixture"))
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "documents", Type: "file-tree", Digest: digest, Files: []spec.FileRecord{{Path: "document.txt", Digest: digest, Size: 7}}})
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "fixture-v2", Namespace: "test", UID: "original-pvc", Annotations: map[string]string{"cinderlock.dev/run": "fixture-run", "cinderlock.dev/model-revision": digest}}}
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Create(context.Background(), claim, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	op := spec.Operation{ID: "seed-fixture", Asset: "documents", PVC: claim.Name}
	if _, err := e.modelVolumeManifest(context.Background(), "fixture-run", op, v); err != nil {
		t.Fatal(err)
	}
	claim.UID = "replacement-pvc"
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Update(context.Background(), claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.modelVolumeManifest(context.Background(), "fixture-run", op, v); spec.ExitCode(err) != 13 {
		t.Fatalf("copied annotations substituted original seeded volume: %v", err)
	}
}
