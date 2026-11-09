package engine

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// Use the native fixture's actual Send/Receive/Verify path, then retain its
// completed operation as an inactive preparation rather than a check fixture.
func completedPreparation(t *testing.T) (*Engine, *fake.Clientset, spec.Plan, *bundle.Verified, spec.TrustPolicy, spec.GitOpsRunReference) {
	t.Helper()
	e, client, p, v, _ := fixtureAcceptanceRun(t, "GitOpsPreparePlan")
	ctx := context.Background()
	e.Site.Spec.Kubeconfig = filepath.Join(e.StateDir, "target.kubeconfig")
	e.Site.Spec.Context = "test"
	siteBody, _ := spec.Canonical(e.Site)
	if err := os.WriteFile(p.SitePath, siteBody, 0600); err != nil {
		t.Fatal(err)
	}
	var policy spec.TrustPolicy
	if err := spec.Read(e.Site.Spec.TrustPolicy, &policy); err != nil {
		t.Fatal(err)
	}
	r := &v.Index.Lock.Release
	r.Spec.Deployment.Type = "gitops"
	r.Spec.Deployment.GitOps = &spec.GitOps{Owner: "argocd", Path: "application.yaml", Revision: strings.Repeat("a", 40)}
	r.Spec.Checks, r.Spec.RequiredChecks = []spec.Check{}, []string{}
	p.SourceVersion, p.TransitionID = "", "gitops-native-preparation"
	p.Checks, p.RequiredChecks = []spec.Check{}, []string{}
	p.SiteDigest, p.PolicyDigest = mustDigest(t, e.Site), mustDigest(t, policy)
	p.SourceSiteDigest, _ = sourceSiteDigest(p.SitePath)
	p.Snapshot, _ = e.inspectArtifacts(ctx)
	p.SnapshotDigest, _ = snapshotDigest(p.Snapshot)
	manifest := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: app}\nspec:\n  selector: {matchLabels: {app: app}}\n  template:\n    metadata: {labels: {app: app}}\n    spec:\n      containers:\n      - name: app\n        image: registry.invalid/app\n        volumeMounts:\n        - {name: model, mountPath: /models, subPath: artifact, readOnly: true}\n      volumes:\n      - name: model\n        persistentVolumeClaim: {claimName: fixtures-v2, readOnly: true}\n")
	manifestPath := filepath.Join(e.StateDir, "reviewed.yaml")
	if err := os.WriteFile(manifestPath, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	p.DesiredStateDigest = spec.Hash(manifest)
	p.GitOps = &spec.GitOpsPlanBinding{Repository: filepath.Join(e.StateDir, "historical-base-no-longer-current"), ManifestPath: manifestPath, Staging: spec.GitOpsRunReference{RunID: "staged", PlanDigest: spec.Hash([]byte("stage-plan")), ResultDigest: spec.Hash([]byte("stage-result"))}}
	worker, err := e.operationWorker(ctx, "fixture-run", p.Operations[0].ID, 1, p.Operations[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	step := spec.StepResult{ID: p.Operations[0].ID, Attempt: 1, Status: "pass", ExternalID: worker.Name, FinishedAt: spec.Now()}
	result := newResult(p, "fixture-run", mustDigest(t, p))
	result.State, result.Acceptance, result.FinishedAt = "gitops_prepared", "not_established", spec.Now()
	result.Steps = []spec.StepResult{step}
	body, _ := spec.Canonical(p)
	evidence, _ := spec.Canonical(step)
	db, err := sql.Open("sqlite", filepath.Join(e.StateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("UPDATE runs SET plan_json=?,plan_digest=? WHERE id='fixture-run'", body, mustDigest(t, p)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE operations SET evidence_json=? WHERE run_id='fixture-run' AND step_id=?", evidence, step.ID); err != nil {
		t.Fatal(err)
	}
	if err = e.Store.SetState(ctx, "fixture-run", result.State, false, result); err != nil {
		t.Fatal(err)
	}
	return e, client, p, v, policy, spec.GitOpsRunReference{RunID: result.RunID, PlanDigest: result.PlanDigest, ResultDigest: mustDigest(t, result)}
}

func preparationChecks(t *testing.T, e *Engine, preparation spec.Plan, ref spec.GitOpsRunReference) spec.Plan {
	t.Helper()
	p := preparation
	p.Kind = "GitOpsChecksPlan"
	p.TransitionID = "gitops-application-checks"
	p.Operations = []spec.Operation{}
	p.Checks, p.RequiredChecks = []spec.Check{}, []string{}
	binding := *p.GitOps
	binding.Repository, binding.Preparation = "", &ref
	binding.Contract = &spec.GitOpsProfileContract{Header: spec.NewHeader("GitOpsProfileContract"), Profile: "argocd-directory-v1", Namespace: "argocd", Name: "application", UID: "application-uid", Repository: e.StateDir, RepositoryURL: "https://git.example.invalid/source.git", AcceptedRevision: strings.Repeat("c", 40), ManifestDigest: p.DesiredStateDigest, NotBefore: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), MaxAgeSeconds: 3600}
	manifest, err := ReadGitOpsManifest(binding.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	repo := newProposalRepository(t, manifest)
	binding.Contract.Repository, binding.Contract.AcceptedRevision = repo.dir, repo.head
	p.GitOps = &binding
	return p
}

func TestGitOpsPreparedVolumeRetainsCrossRunNativeProvenance(t *testing.T) {
	e, client, preparation, v, policy, ref := completedPreparation(t)
	ctx := context.Background()
	filled, err := e.gitOpsPreparationReference(ctx, spec.GitOpsRunReference{RunID: ref.RunID}, v, preparation.SitePath, policy)
	if err != nil || filled != ref {
		t.Fatalf("historical preparation was not exactly resolved: %#v %v", filled, err)
	}
	p := preparationChecks(t, e, preparation, ref)
	// This is a different local run; the prior preparation's fixture must not
	// become an implicit same-run fixture for it.
	body, _ := spec.Canonical(p)
	site, _ := spec.Canonical(e.Site)
	if err := e.Store.CreateRun(ctx, state.Run{ID: "checks-run", Application: p.Metadata.Application, TargetID: p.Snapshot.TargetID, Namespace: "test", BundleDigest: v.Digest, PlanDigest: mustDigest(t, p), Plan: body, Site: site}); err != nil {
		t.Fatal(err)
	}
	if err := client.AppsV1().Deployments("test").Delete(ctx, "app", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	volume, err := e.gitOpsPreparedVolume(ctx, p, v, "fixtures-v2")
	if err != nil {
		t.Fatal(err)
	}
	if volume.Preparation != ref || volume.Receiver.Worker.UID == "" || volume.Receiver.PodUID == "" || volume.PVCUID != "uid-fixtures-v2" || volume.Verifier.UID == "" {
		t.Fatalf("original native identities lost: %#v", volume)
	}
	if _, err := e.resolveFixtureBindings(ctx, "checks-run", preparation, spec.Check{ID: "fixture", Type: "job", Fixtures: []string{"documents"}}, v); err == nil {
		t.Fatal("cross-run preparation bypassed dedicated fixture provenance")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Fatalf("provenance read mutated %s", action.GetResource().Resource)
		}
	}
}

func TestGitOpsPreparedVolumeRejectsChangedOriginalEvidence(t *testing.T) {
	for _, change := range []string{"pvc", "manifest-uid", "manifest-data", "receiver-job", "receiver-pod", "receiver-recipe", "verifier", "missing-verifier", "running-receiver-job", "active-preparation", "plan-reference", "result-reference", "receipt", "target"} {
		t.Run(change, func(t *testing.T) {
			e, client, preparation, v, _, ref := completedPreparation(t)
			p := preparationChecks(t, e, preparation, ref)
			ctx := context.Background()
			volume, err := e.gitOpsPreparedVolume(ctx, p, v, "fixtures-v2")
			if err != nil {
				t.Fatal("control preparation failed", err)
			}
			switch change {
			case "pvc":
				pvc, _ := client.CoreV1().PersistentVolumeClaims("test").Get(ctx, volume.PVC, metav1.GetOptions{})
				pvc.UID = "replacement"
				_, err = client.CoreV1().PersistentVolumeClaims("test").Update(ctx, pvc, metav1.UpdateOptions{})
			case "manifest-uid", "manifest-data":
				manifest, _ := client.CoreV1().ConfigMaps("test").Get(ctx, volume.Manifest, metav1.GetOptions{})
				if change == "manifest-uid" {
					manifest.UID = "replacement"
				} else {
					manifest.Data["files.json"] = "[]"
				}
				_, err = client.CoreV1().ConfigMaps("test").Update(ctx, manifest, metav1.UpdateOptions{})
			case "receiver-job", "verifier", "running-receiver-job":
				name := volume.Receiver.Worker.Name
				if change == "verifier" {
					name = volume.Verifier.Name
				}
				job, _ := client.BatchV1().Jobs("test").Get(ctx, name, metav1.GetOptions{})
				if change == "running-receiver-job" {
					job.Status.Conditions = nil
				} else {
					job.UID = "replacement"
				}
				_, err = client.BatchV1().Jobs("test").Update(ctx, job, metav1.UpdateOptions{})
			case "missing-verifier":
				err = client.BatchV1().Jobs("test").Delete(ctx, volume.Verifier.Name, metav1.DeleteOptions{})
			case "receiver-pod", "receiver-recipe":
				pod, _ := client.CoreV1().Pods("test").Get(ctx, volume.Receiver.PodName, metav1.GetOptions{})
				if change == "receiver-pod" {
					pod.UID = "replacement"
				} else {
					pod.Spec.Containers[0].Image = "different"
				}
				_, err = client.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{})
			case "active-preparation":
				err = e.Store.SetState(ctx, ref.RunID, "gitops_prepared", true, nil)
			case "plan-reference":
				p.GitOps.Preparation.PlanDigest = spec.Hash([]byte("different"))
			case "result-reference":
				p.GitOps.Preparation.ResultDigest = spec.Hash([]byte("different"))
			case "receipt":
				db, openErr := sql.Open("sqlite", filepath.Join(e.StateDir, "state.db"))
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer db.Close()
				_, err = db.Exec("UPDATE operations SET evidence_json='{}' WHERE run_id=?", ref.RunID)
			case "target":
				ns, _ := client.CoreV1().Namespaces().Get(ctx, "test", metav1.GetOptions{})
				ns.UID = "replacement"
				_, err = client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if _, err := e.gitOpsPreparedVolume(ctx, p, v, "fixtures-v2"); err == nil {
				t.Fatal("changed native evidence was accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatalf("rejection mutated %s", action.GetResource().Resource)
				}
			}
		})
	}
}

func preparedDeployment(t *testing.T, client *fake.Clientset, p spec.Plan) (*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod) {
	t.Helper()
	manifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := PermissionObjects(manifest)
	if err != nil {
		t.Fatal(err)
	}
	deployment := &appsv1.Deployment{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(objects[0], deployment); err != nil {
		t.Fatal(err)
	}
	deployment.Namespace, deployment.UID = "test", "reviewed-deployment"
	ctx := context.Background()
	if _, err := client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	yes := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "app-replicaset", Namespace: "test", UID: "reviewed-replicaset", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", APIVersion: "apps/v1", Name: deployment.Name, UID: deployment.UID, Controller: &yes}}}, Spec: appsv1.ReplicaSetSpec{Selector: deployment.Spec.Selector.DeepCopy(), Template: *deployment.Spec.Template.DeepCopy()}}
	if _, err := client.AppsV1().ReplicaSets("test").Create(ctx, rs, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "test", UID: "reviewed-pod", Labels: deployment.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", APIVersion: "apps/v1", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: *deployment.Spec.Template.Spec.DeepCopy()}
	if _, err := client.CoreV1().Pods("test").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return deployment, rs, pod
}

func TestGitOpsPreparedVolumeRejectsUnknownAndWritableConsumers(t *testing.T) {
	for _, change := range []string{"unknown-readonly", "unknown-job", "writable-claim", "writable-mount", "subpath", "mount-path", "shadowed-mount", "extra-container", "ephemeral", "replicaset-uid", "deployment-owner", "deployment-uid"} {
		t.Run(change, func(t *testing.T) {
			e, client, preparation, v, _, ref := completedPreparation(t)
			p := preparationChecks(t, e, preparation, ref)
			deployment, rs, pod := preparedDeployment(t, client, p)
			ctx := context.Background()
			if _, err := e.gitOpsPreparedVolume(ctx, p, v, "fixtures-v2"); err != nil {
				t.Fatal("reviewed read-only Deployment chain rejected", err)
			}
			switch change {
			case "unknown-readonly":
				pod.OwnerReferences = nil
			case "unknown-job":
				pod.OwnerReferences[0].Kind, pod.OwnerReferences[0].APIVersion = "Job", "batch/v1"
			case "writable-claim":
				pod.Spec.Volumes[0].PersistentVolumeClaim.ReadOnly = false
			case "writable-mount":
				pod.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "other"
			case "mount-path":
				pod.Spec.Containers[0].VolumeMounts[0].MountPath = "/other"
			case "shadowed-mount":
				pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "overlay", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "overlay", MountPath: "/models/weights"})
			case "extra-container":
				extra := *pod.Spec.Containers[0].DeepCopy()
				extra.Name = "another"
				pod.Spec.Containers = append(pod.Spec.Containers, extra)
			case "ephemeral":
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"}}}
			case "replicaset-uid":
				rs.UID = "replacement"
			case "deployment-owner":
				rs.OwnerReferences[0].UID = "other-deployment"
			case "deployment-uid":
				deployment.UID = "replacement"
			}
			if _, err := client.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.AppsV1().ReplicaSets("test").Update(ctx, rs, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if _, err := e.gitOpsPreparedVolume(ctx, p, v, "fixtures-v2"); err == nil {
				t.Fatal("unknown or changed prepared claim consumer accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("consumer inspection mutated the target")
				}
			}
		})
	}
}

func TestGitOpsPreparationRejectsReferencedFreshClaim(t *testing.T) {
	for _, consumer := range []string{"deployment", "replicaset", "job", "cronjob", "pod"} {
		t.Run(consumer, func(t *testing.T) {
			e, client, p, v, _, _ := completedPreparation(t)
			manifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest = []byte(strings.ReplaceAll(string(manifest), "fixtures-v2", "fresh-v3"))
			p.Operations = append([]spec.Operation{}, p.Operations...)
			p.Operations[0].PVC = "fresh-v3"
			ctx := context.Background()
			facts, err := e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, p.Snapshot.TargetID)
			if err != nil || len(facts) != 1 || facts[0].Value != "false" {
				t.Fatal("empty fresh destination was not recognized", facts, err)
			}
			pod := corev1.PodSpec{Volumes: []corev1.Volume{{Name: "model", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "fresh-v3", ReadOnly: true}}}}}
			metadata := metav1.ObjectMeta{Name: "unknown", Namespace: "test", UID: "unknown"}
			switch consumer {
			case "deployment":
				_, err = client.AppsV1().Deployments("test").Create(ctx, &appsv1.Deployment{ObjectMeta: metadata, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: pod}}}, metav1.CreateOptions{})
			case "replicaset":
				_, err = client.AppsV1().ReplicaSets("test").Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metadata, Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{Spec: pod}}}, metav1.CreateOptions{})
			case "job":
				err = client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), &batchv1.Job{ObjectMeta: metadata, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: pod}}}, "test")
			case "cronjob":
				_, err = client.BatchV1().CronJobs("test").Create(ctx, &batchv1.CronJob{ObjectMeta: metadata, Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: pod}}}}}, metav1.CreateOptions{})
			case "pod":
				_, err = client.CoreV1().Pods("test").Create(ctx, &corev1.Pod{ObjectMeta: metadata, Spec: pod}, metav1.CreateOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			if _, err := e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, p.Snapshot.TargetID); err == nil {
				t.Fatal("fresh destination accepted a preexisting consumer reference")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("fresh-destination inspection mutated the target")
				}
			}
		})
	}
}

func TestGitOpsPreparationRequiresCurrentActiveRunAndIgnoresBookkeeping(t *testing.T) {
	e, client, p, v, _, ref := completedPreparation(t)
	ctx := context.Background()
	manifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, p.Snapshot.TargetID); err == nil {
		t.Fatal("inactive prior preparation was adopted as this run's destination")
	}
	if err := e.Store.SetState(ctx, ref.RunID, "running", true, nil); err != nil {
		t.Fatal(err)
	}
	facts, err := e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, p.Snapshot.TargetID)
	if err != nil || len(facts) != 1 || facts[0].Value != "true" {
		t.Fatal("exact active native preparation was not recognized", facts, err)
	}
	before := p.Snapshot
	before.Facts = append(before.Facts, facts...)
	pvc, _ := client.CoreV1().PersistentVolumeClaims("test").Get(ctx, p.Operations[0].PVC, metav1.GetOptions{})
	pvc.ResourceVersion, pvc.CreationTimestamp = "updated", metav1.Now()
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Update(ctx, pvc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	workers, err := e.Store.Workers(ctx, ref.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for _, worker := range workers {
		job, _ := client.BatchV1().Jobs("test").Get(ctx, worker.Name, metav1.GetOptions{})
		job.ResourceVersion, job.CreationTimestamp = "updated", metav1.Now()
		job.Status.CompletionTime = &metav1.Time{Time: time.Now()}
		if _, err := client.BatchV1().Jobs("test").Update(ctx, job, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	client.ClearActions()
	after := p.Snapshot
	after.Facts, err = e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, p.Snapshot.TargetID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := snapshotDigest(before)
	b, _ := snapshotDigest(after)
	if a != b {
		t.Fatal("native status, resource version or timestamps changed the semantic snapshot")
	}
	other := p
	other.CreatedAt = spec.Now()
	if _, err := e.gitOpsPreparationSeedFacts(ctx, other, v, manifest, p.Snapshot.TargetID); err == nil {
		t.Fatal("another plan inherited the active preparation")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Fatal("active preparation inspection mutated the target")
		}
	}
}

func TestGitOpsPreparationUsesFrozenInstallRenderAndExactBase(t *testing.T) {
	for _, scenario := range []string{"absent", "uninstalled", "active", "dirty-base", "wrong-render", "internal-input"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProfileFixture(t)
			e, v := f.e, f.v
			store, err := state.Open(filepath.Join(e.StateDir, "preparation.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			e.Store = store
			e.Site.Spec.HelperImage = v.Index.Lock.Assets[len(v.Index.Lock.Assets)-1].Digest
			e.Site.Spec.CapacityBytes = 100000
			site, _ := spec.Canonical(e.Site)
			if err := os.WriteFile(f.sitePath, site, 0600); err != nil {
				t.Fatal(err)
			}
			seed := spec.Operation{ID: "seed-model", Type: "seed", Asset: "model", PVC: "model-v2", MountPath: "/models", StorageBytes: 1024}
			v.Index.Lock.Release.Spec.Operations = append(v.Index.Lock.Release.Spec.Operations, seed)
			v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "model", Type: "model-tree", Digest: spec.Hash([]byte("model")), Files: []spec.FileRecord{{Path: "weights", Digest: spec.Hash([]byte("x")), Size: 1}}})
			manifestPath := filepath.Join(e.StateDir, "reviewed.yaml")
			if scenario == "internal-input" {
				manifestPath = filepath.Join(f.repo.dir, "reviewed.yaml")
			}
			if err := os.WriteFile(manifestPath, f.manifest, 0600); err != nil {
				t.Fatal(err)
			}
			if scenario == "dirty-base" {
				if err := os.WriteFile(filepath.Join(f.repo.dir, "application.yaml"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			templates := 0
			e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
				switch args[0] {
				case "history":
					if scenario == "active" {
						return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
					}
					if scenario == "uninstalled" {
						return []byte(`[{"revision":1,"status":"uninstalled","app_version":"1.0.0"}]`), nil
					}
					return nil, errors.New("release: not found")
				case "template":
					templates++
					for _, arg := range args {
						if arg == "--is-upgrade" {
							t.Fatal("preparation rendered in upgrade context")
						}
					}
					if scenario == "wrong-render" {
						return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: other}\n"), nil
					}
					return f.manifest, nil
				default:
					t.Fatalf("preparation read active values or invoked a Helm writer: %s", args[0])
					return nil, nil
				}
			}
			p := spec.Plan{Header: spec.NewHeader("GitOpsPreparePlan"), BundleDigest: v.Digest, BundlePath: filepath.Join(e.StateDir, "bundle.cinder"), SitePath: f.sitePath, SiteDigest: mustDigest(t, e.Site), PolicyDigest: mustDigest(t, f.policy), PolicyEpoch: f.policy.Spec.Epoch, DesiredStateDigest: spec.Hash(f.manifest), TargetVersion: v.Index.Lock.Release.Metadata.Version, TransitionID: "gitops-native-preparation", Operations: []spec.Operation{seed}, Checks: []spec.Check{}, RequiredChecks: []string{}, GitOps: &spec.GitOpsPlanBinding{ManifestPath: manifestPath, Repository: f.repo.dir, Staging: spec.GitOpsRunReference{RunID: "missing-stage", PlanDigest: spec.Hash([]byte("plan")), ResultDigest: spec.Hash([]byte("result"))}}}
			p.Metadata = v.Index.Lock.Release.Metadata
			p.SourceSiteDigest, _ = sourceSiteDigest(f.sitePath)
			f.kube.ClearActions()
			snapshot, err := e.inspectGitOpsPreparation(context.Background(), p, v, f.policy)
			if err == nil {
				t.Fatal("unavailable staging was accepted")
			}
			if scenario == "absent" || scenario == "uninstalled" {
				if templates != 1 || !strings.Contains(err.Error(), "required GitOps phase") {
					t.Fatal("frozen render and local BASE did not reach the explicit staging guard", templates, err)
				}
			} else if scenario == "active" || scenario == "internal-input" {
				if templates != 0 {
					t.Fatal("unsafe ownership/input was discovered after rendering")
				}
			} else if spec.ExitCode(err) != 11 {
				t.Fatal("reviewed render/source mismatch was not rejected", err)
			}
			body, _ := spec.Canonical(snapshot)
			if strings.Contains(string(body)+err.Error(), "CONFIGMAP-SENSITIVE-SENTINEL") {
				t.Fatal("preparation exposed reviewed ConfigMap values")
			}
			for _, action := range f.kube.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("preparation inspection mutated the target")
				}
			}
		})
	}
}

func TestGitOpsPreparationRejectsAdditionalSeedEffects(t *testing.T) {
	e, client, original, verified, _, _ := completedPreparation(t)
	if err := e.verifyGitOpsPreparation(original, verified); err != nil {
		t.Fatal("native control recipe failed", err)
	}
	for _, effect := range []string{"reconcile-command", "service", "destructive", "exit-code", "shared-claim", "mutable-data"} {
		t.Run(effect, func(t *testing.T) {
			p, v := original, *verified
			p.Operations = append([]spec.Operation{}, original.Operations...)
			v.Index.Lock.Assets = append([]spec.LockedAsset{}, verified.Index.Lock.Assets...)
			switch effect {
			case "reconcile-command":
				p.Operations[0].ReconcileCommand = []string{"/unexpected"}
			case "service":
				p.Operations[0].Service = "unexpected"
			case "destructive":
				p.Operations[0].Destructive = true
			case "exit-code":
				p.Operations[0].ExpectedExitCode = 1
			case "shared-claim":
				other := p.Operations[0]
				other.ID, other.Asset = "another-seed", "another-asset"
				p.Operations = append(p.Operations, other)
				asset, err := verified.Asset(p.Operations[0].Asset)
				if err != nil {
					t.Fatal(err)
				}
				asset.ID = other.Asset
				v.Index.Lock.Assets = append(v.Index.Lock.Assets, asset)
			case "mutable-data":
				for i := range v.Index.Lock.Assets {
					if v.Index.Lock.Assets[i].ID == p.Operations[0].Asset {
						v.Index.Lock.Assets[i].Type = "database"
					}
				}
			}
			v.Index.Lock.Release.Spec.Operations = p.Operations
			client.ClearActions()
			if err := e.verifyGitOpsPreparation(p, &v); err == nil {
				t.Fatal("additional seed effect was accepted")
			}
			if len(client.Actions()) != 0 {
				t.Fatal("unsupported recipe contacted the target")
			}
		})
	}
}
