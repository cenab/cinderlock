package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

type gitOpsExecutionFixture struct {
	*profileFixture
	binding          spec.GitOpsPlanBinding
	key              ed25519.PrivateKey
	prepared         *spec.RunResult
	modelRoot        string
	preparationPlan  spec.Plan
	preparationError error
}

func newGitOpsExecutionFixture(t *testing.T, models bool, preparationMode ...string) *gitOpsExecutionFixture {
	t.Helper()
	ctx := context.Background()
	f := newProfileFixture(t)
	storeEngine, _, imageBundle, _, _, _ := stagedImageFixture(t)
	f.e.Store = storeEngine.Store
	f.kube.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	oldImage, err := f.e.image(f.v, "runner")
	if err != nil {
		t.Fatal(err)
	}
	f.e.Site.Spec.Registry = storeEngine.Site.Spec.Registry
	f.e.Site.Spec.RegistryPlainHTTP = true
	f.e.Site.Spec.AllowedActions = []string{"gitops-stage", "import", "registry-http", "gitops-observe", "gitops-check", "gitops-prepare", "seed", "job"}
	for _, file := range imageBundle.Index.Lock.Assets[0].Files {
		path, err := bundle.BlobPath(imageBundle.Root, file.Digest)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := bundle.Store(ctx, f.v.Root, bytes.NewReader(body), bundle.MaxPayloadBytes); err != nil {
			t.Fatal(err)
		}
	}
	for i := range f.v.Index.Lock.Assets {
		if f.v.Index.Lock.Assets[i].ID == "runner" {
			f.v.Index.Lock.Assets[i] = imageBundle.Index.Lock.Assets[0]
		}
	}
	newImage, err := f.e.image(f.v, "runner")
	if err != nil {
		t.Fatal(err)
	}
	f.e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"workflow-token": {Name: "workflow-token", Key: "token"}}
	if _, err := f.kube.CoreV1().Secrets("test").Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "workflow-token", Namespace: "test", UID: "workflow-token-uid"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"token": []byte("private-test-token")}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	check := spec.Check{ID: "workflow", Type: "job", Domain: "workflow", Required: true, Image: "runner", Command: []string{"/app/check"}, SecretRefs: []string{"workflow-token"}, TimeoutSeconds: 1, Script: fixtureScript("workflow")}
	f.v.Index.Lock.Release.Spec.Checks = []spec.Check{check}
	f.v.Index.Lock.Release.Spec.RequiredChecks = []string{check.ID}
	var modelFiles []spec.FileRecord
	filesByClaim := map[string][]spec.FileRecord{}
	if models {
		content := []byte("bounded test model")
		digest, size, err := bundle.Store(ctx, f.v.Root, bytes.NewReader(content), bundle.MaxPayloadBytes)
		if err != nil {
			t.Fatal(err)
		}
		modelFiles = []spec.FileRecord{{Path: "weights.bin", Digest: digest, Size: size}}
		filesByClaim["model-v2"] = modelFiles
		f.v.Index.Lock.Assets = append(f.v.Index.Lock.Assets, spec.LockedAsset{ID: "model", Type: "file-tree", Digest: mustDigest(t, modelFiles), Files: modelFiles})
		f.v.Index.Lock.Release.Spec.Assets = append(f.v.Index.Lock.Release.Spec.Assets, spec.Asset{ID: "model", Type: "file-tree", Source: "model"})
		seed := spec.Operation{ID: "seed-model", Type: "seed", Asset: "model", PVC: "model-v2", MountPath: "/models", StorageBytes: 1024, TimeoutSeconds: 5}
		f.v.Index.Lock.Release.Spec.Operations = append([]spec.Operation{seed}, f.v.Index.Lock.Release.Spec.Operations...)
		f.v.Index.Lock.Release.Spec.Operations[1].DependsOn = []string{seed.ID}
		f.v.Index.Lock.Release.Spec.Transitions[0].Operations = []string{seed.ID, "sync"}
		fixtureContent := []byte("dedicated workflow fixture")
		fixtureDigest, fixtureSize, err := bundle.Store(ctx, f.v.Root, bytes.NewReader(fixtureContent), bundle.MaxPayloadBytes)
		if err != nil {
			t.Fatal(err)
		}
		fixtureFiles := []spec.FileRecord{{Path: "document.txt", Digest: fixtureDigest, Size: fixtureSize}}
		filesByClaim["fixture-v2"] = fixtureFiles
		f.v.Index.Lock.Assets = append(f.v.Index.Lock.Assets, spec.LockedAsset{ID: "documents", Type: "file-tree", Digest: mustDigest(t, fixtureFiles), Files: fixtureFiles})
		f.v.Index.Lock.Release.Spec.Assets = append(f.v.Index.Lock.Release.Spec.Assets, spec.Asset{ID: "documents", Type: "file-tree", Source: "documents"})
		fixtureSeed := spec.Operation{ID: "seed-fixture", Type: "seed", Asset: "documents", PVC: "fixture-v2", MountPath: "/documents", DependsOn: []string{"sync"}, StorageBytes: 1024, TimeoutSeconds: 5}
		f.v.Index.Lock.Release.Spec.Operations = append(f.v.Index.Lock.Release.Spec.Operations, fixtureSeed)
		f.v.Index.Lock.Release.Spec.Transitions[0].Operations = append(f.v.Index.Lock.Release.Spec.Transitions[0].Operations, fixtureSeed.ID)
		f.v.Index.Lock.Release.Spec.Checks[0].Fixtures = []string{"documents"}
		f.e.Site.Spec.HelperImage = imageBundle.Index.Lock.Assets[0].Digest
		f.e.Site.Spec.CapacityBytes = 100000
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.Spec.Epoch = 3
	f.policy.Spec.RequireAuthorization = true
	f.policy.Spec.AllowedActions = append([]string{}, f.e.Site.Spec.AllowedActions...)
	f.policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"approval"}}}
	if err := os.WriteFile(f.sitePath, mustCanonical(t, f.e.Site), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.e.Site.Spec.TrustPolicy, mustCanonical(t, f.policy), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.e.inspectArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.e.Store.ObservePolicyFloor(ctx, snapshot.TargetID, f.policy.Spec.Epoch, mustDigest(t, f.policy)); err != nil {
		t.Fatal(err)
	}
	originalRenderer := f.e.HelmRunner
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "get" {
			t.Fatal("GitOps execution read active Helm values")
		}
		body, err := originalRenderer(ctx, args...)
		if args[0] == "template" {
			body = bytes.ReplaceAll(body, []byte(oldImage), []byte(newImage))
			if models {
				objects, err := PermissionObjects(body)
				if err != nil {
					return nil, err
				}
				pod := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				pod["volumes"] = []any{map[string]any{"name": "models", "persistentVolumeClaim": map[string]any{"claimName": "model-v2"}}}
				pod["containers"].([]any)[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "models", "mountPath": "/models", "readOnly": true}}
				return encodeObjects(objects)
			}
		}
		return body, err
	}
	f.manifest, err = f.e.RenderDesiredState(ctx, f.v)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(f.e.StateDir, "reviewed-target.yaml")
	if err := os.WriteFile(manifestPath, f.manifest, 0600); err != nil {
		t.Fatal(err)
	}
	stage, err := f.e.ArtifactsPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy)
	if err != nil || !stage.Executable {
		t.Fatalf("image staging plan is blocked: %v %#v", err, stage.Findings)
	}
	fixture := &gitOpsExecutionFixture{profileFixture: f, key: private}
	staged, err := f.e.Apply(ctx, stage, f.v, f.policy, fixture.approval(t, stage), false)
	if err != nil || staged.State != "artifacts_staged" {
		t.Fatalf("actual image staging failed: %v %#v", err, staged)
	}
	f.kube.PrependReactor("create", "persistentvolumeclaims", func(action ktesting.Action) (bool, runtime.Object, error) {
		pvc := action.(ktesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim)
		pvc.UID = types.UID("uid-" + pvc.Name)
		return false, nil, nil
	})
	f.kube.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		cm := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap)
		cm.UID = types.UID("uid-" + cm.Name)
		return false, nil, nil
	})
	roots := map[string]string{}
	for claim := range filesByClaim {
		roots[claim] = t.TempDir()
	}
	fixture.modelRoot = roots["model-v2"]
	claimOf := func(pod corev1.PodSpec) string {
		for _, volume := range pod.Volumes {
			if volume.PersistentVolumeClaim != nil {
				return volume.PersistentVolumeClaim.ClaimName
			}
		}
		return ""
	}
	f.kube.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		container := job.Spec.Template.Spec.Containers[0]
		if container.Stdin {
			yes := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: "test", UID: types.UID("pod-" + job.Name), Labels: job.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "operation", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			if err := f.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, "test"); err != nil {
				t.Fatal(err)
			}
		} else {
			condition := batchv1.JobComplete
			if len(container.Command) > 2 && container.Command[2] == "verify-model" {
				claim := claimOf(job.Spec.Template.Spec)
				if err := modelstage.Verify(roots[claim], filesByClaim[claim]); err != nil {
					condition = batchv1.JobFailed
				}
			}
			job.Status.Conditions = []batchv1.JobCondition{{Type: condition, Status: corev1.ConditionTrue}}
		}
		return false, nil, nil
	})
	f.e.ModelAttach = func(ctx context.Context, name string, input io.Reader, _, _ io.Writer) error {
		pod, err := f.kube.CoreV1().Pods("test").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		claim := claimOf(pod.Spec)
		if err := modelstage.Receive(ctx, roots[claim], "", filesByClaim[claim], input); err != nil {
			return err
		}
		pod.Status.Phase = corev1.PodSucceeded
		pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
		if _, err := f.kube.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
			return err
		}
		job, err := f.kube.BatchV1().Jobs("test").Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		_, err = f.kube.BatchV1().Jobs("test").UpdateStatus(ctx, job, metav1.UpdateOptions{})
		return err
	}
	if models {
		binding := spec.GitOpsPlanBinding{ManifestPath: manifestPath, Repository: f.repo.dir, Staging: spec.GitOpsRunReference{RunID: staged.RunID}}
		plan, err := f.e.GitOpsPreparePlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, binding, spec.Hash(f.manifest))
		if err != nil || !plan.Executable {
			t.Fatalf("native preparation plan blocked: %v %#v", err, plan.Findings)
		}
		authorization := fixture.approval(t, plan)
		if len(preparationMode) > 0 {
			originalAttach := f.e.ModelAttach
			f.e.ModelAttach = func(ctx context.Context, name string, input io.Reader, stdout, stderr io.Writer) error {
				if err := originalAttach(ctx, name, input, stdout, stderr); err != nil {
					return err
				}
				if preparationMode[0] == "source" {
					return os.WriteFile(filepath.Join(f.repo.dir, "application.yaml"), []byte("source changed during transfer"), 0600)
				}
				authorization.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
				return spec.SignAuthorization(authorization, fixture.key, "customer")
			}
		}
		result, err := f.e.Apply(ctx, plan, f.v, f.policy, authorization, false)
		if len(preparationMode) > 0 {
			fixture.preparationPlan, fixture.preparationError, fixture.prepared = plan, err, &result
			return fixture
		}
		if err != nil || result.State != "gitops_prepared" || result.Acceptance != "not_established" {
			t.Fatalf("native preparation did not complete separately: %v %#v", err, result)
		}
		fixture.prepared = &result
	}
	base := f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision
	proposal, err := ProposeGitOpsSource(ctx, f.repo.dir, base, "application.yaml", f.manifest)
	if err != nil || proposal.Patch == "" {
		t.Fatalf("nonempty base-to-target proposal unavailable: %v %#v", err, proposal)
	}
	f.repo.command([]byte(proposal.Patch), "apply", "-")
	f.repo.command(nil, "add", "--", "application.yaml")
	f.repo.command(nil, "commit", "-m", "Fixture accepted source")
	accepted := strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD")))
	f.accepted(t, accepted)
	// The same signed bundle retains its proposal base; C is independently selected.
	f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision = base
	f.contract.ManifestDigest = spec.Hash(f.manifest)
	if accepted == base {
		t.Fatal("fixture source did not advance beyond the signed base")
	}
	for _, resource := range f.live {
		if resource.GetKind() == "Deployment" {
			containers, _, err := unstructured.NestedSlice(resource.Object, "spec", "template", "spec", "containers")
			if err != nil {
				t.Fatal(err)
			}
			containers[0].(map[string]any)["image"] = newImage
			if models {
				containers[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "models", "mountPath": "/models", "readOnly": true}}
				profileSet(t, resource, []any{map[string]any{"name": "models", "persistentVolumeClaim": map[string]any{"claimName": "model-v2"}}}, "spec", "template", "spec", "volumes")
				fields, _, err := unstructured.NestedSlice(resource.Object, "metadata", "managedFields")
				if err != nil {
					t.Fatal(err)
				}
				podFields := fields[0].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)["f:template"].(map[string]any)["f:spec"].(map[string]any)
				podFields["f:volumes"] = map[string]any{`k:{"name":"models"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:persistentVolumeClaim": map[string]any{"f:claimName": map[string]any{}}}}
				podFields["f:containers"].(map[string]any)[`k:{"name":"app"}`].(map[string]any)["f:volumeMounts"] = map[string]any{`k:{"mountPath":"/models"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:mountPath": map[string]any{}, "f:readOnly": map[string]any{}}}
				profileSet(t, resource, fields, "metadata", "managedFields")
			}
			profileSet(t, resource, containers, "spec", "template", "spec", "containers")
		}
	}
	f.seed(t)
	fixture.binding = spec.GitOpsPlanBinding{ManifestPath: manifestPath, Staging: spec.GitOpsRunReference{RunID: staged.RunID}, Contract: &f.contract}
	if fixture.prepared != nil {
		fixture.binding.Preparation = &spec.GitOpsRunReference{RunID: fixture.prepared.RunID}
	}
	return fixture
}

func (f *gitOpsExecutionFixture) approval(t *testing.T, p spec.Plan) *spec.Authorization {
	t.Helper()
	a := &spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: mustDigest(t, p), PlanKind: p.Kind, TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: p.PolicyEpoch, Actions: spec.PlanActions(p), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: randomID()}
	if err := spec.SignAuthorization(a, f.key, "customer"); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestGitOpsPreparedModelsReachAuthorizedApplicationChecks(t *testing.T) {
	f := newGitOpsExecutionFixture(t, true)
	ctx := context.Background()
	if f.prepared == nil || f.binding.Preparation == nil {
		t.Fatal("native preparation did not produce a separate durable reference")
	}
	prepared, err := f.e.Store.Run(ctx, f.prepared.RunID)
	if err != nil || prepared.Active {
		t.Fatalf("completed fresh-model preparation kept the mutation gate: %v %#v", err, prepared)
	}
	floor, err := f.e.Store.ReleaseFloor(ctx, f.prepared.TargetID, "app", "stable")
	if err != nil || floor != 0 {
		t.Fatalf("model materialization advanced application acceptance: %d %v", floor, err)
	}
	p, err := f.e.GitOpsChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil || !p.Executable {
		observation, observed := f.observe()
		t.Fatalf("prepared accepted source could not produce a check plan: %v %#v observer=%v %#v", err, p.Findings, observed, observation.Findings)
	}
	result, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
	if err != nil || result.State != "succeeded" || result.Acceptance != "pass" {
		t.Fatalf("authorized model checks did not establish their workflows: %v %#v", err, result)
	}
	if len(result.Checks) != 1 || result.Checks[0].Status != "pass" {
		t.Fatalf("authored workflow evidence is missing: %#v", result.Checks)
	}
	for _, phase := range []string{"start", "finish"} {
		intent, err := f.e.Store.LatestOperation(ctx, result.RunID, gitOpsModelStep(phase, "model"))
		if err != nil || intent.State != "complete" {
			t.Fatalf("%s model verification lacks a durable completed receipt: %v %#v", phase, err, intent)
		}
	}
	workers, err := f.e.Store.Workers(ctx, result.RunID)
	if err != nil || len(workers) != 6 {
		t.Fatalf("checks must retain two model scans, same-run fixture receiver/two verifiers and authored worker: %v %#v", err, workers)
	}
	floor, err = f.e.Store.ReleaseFloor(ctx, p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
	if err != nil || floor != p.Metadata.Sequence {
		t.Fatalf("completed authored workflows did not advance the exact release floor: %d %v", floor, err)
	}
}

func TestGitOpsChecksRunBindsAcceptedSourceStageAndFinalCheckpoint(t *testing.T) {
	for _, change := range []string{"bookkeeping", "resource-uid", "secret-data", "source"} {
		t.Run(change, func(t *testing.T) {
			f := newGitOpsExecutionFixture(t, false)
			p, err := f.e.GitOpsChecksPlan(context.Background(), f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
			if err != nil || !p.Executable {
				t.Fatalf("check plan blocked: %v %#v", err, p.Findings)
			}
			if _, err := f.e.Apply(context.Background(), p, f.v, f.policy, nil, false); spec.ExitCode(err) != 16 {
				t.Fatal("controller readiness granted unsigned check execution", err)
			}
			f.kube.PrependReactor("create", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
				switch change {
				case "bookkeeping", "resource-uid":
					resource := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
					object, err := f.client.Tracker().Get(resource, "test", "app")
					if err != nil {
						t.Fatal(err)
					}
					u := object.(*unstructured.Unstructured)
					u.SetResourceVersion("later-bookkeeping")
					if change == "resource-uid" {
						u.SetUID("replacement")
					}
					if err := f.client.Tracker().Update(resource, u, "test"); err != nil {
						t.Fatal(err)
					}
				case "secret-data":
					resource := corev1.SchemeGroupVersion.WithResource("secrets")
					object, err := f.kube.Tracker().Get(resource, "test", "workflow-token")
					if err != nil {
						t.Fatal(err)
					}
					object.(*corev1.Secret).Data["token"] = []byte("changed")
					if err := f.kube.Tracker().Update(resource, object, "test"); err != nil {
						t.Fatal(err)
					}
				case "source":
					if err := os.WriteFile(filepath.Join(f.repo.dir, "application.yaml"), []byte("changed source"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return false, nil, nil
			})
			result, err := f.e.Apply(context.Background(), p, f.v, f.policy, f.approval(t, p), false)
			floor, floorErr := f.e.Store.ReleaseFloor(context.Background(), p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
			if change == "bookkeeping" {
				if err != nil || result.State != "succeeded" || result.Acceptance != "pass" || floorErr != nil || floor != p.Metadata.Sequence {
					t.Fatalf("exact approved check phase failed: %v floor=%d/%v result=%#v", err, floor, floorErr, result)
				}
			} else if err == nil || result.Acceptance == "pass" || floorErr != nil || floor != 0 {
				t.Fatalf("last-check %s drift accepted: %v floor=%d/%v result=%#v", change, err, floor, floorErr, result)
			}
			if len(result.Checks) != 1 || result.Checks[0].ID != "workflow" || result.Checks[0].Status != "pass" {
				t.Fatalf("original successful check evidence was lost: %#v", result.Checks)
			}
		})
	}
}

func TestGitOpsModelBytesChangedDuringWorkflowCannotPassAcceptance(t *testing.T) {
	f := newGitOpsExecutionFixture(t, true)
	ctx := context.Background()
	p, err := f.e.GitOpsChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil || !p.Executable {
		t.Fatalf("model checks were blocked before the experiment: %v %#v", err, p.Findings)
	}
	changed := false
	f.kube.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		if job.Spec.Template.Spec.Containers[0].Command[0] == "/app/check" {
			changed = true
			if err := os.WriteFile(filepath.Join(f.modelRoot, "weights.bin"), []byte("changed outside the read-only application mount"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return false, nil, nil
	})
	result, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
	floor, floorErr := f.e.Store.ReleaseFloor(ctx, p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
	if !changed || err == nil || result.Acceptance == "pass" || floorErr != nil || floor != 0 {
		t.Fatalf("changed model bytes were accepted: changed=%v error=%v floor=%d/%v result=%#v", changed, err, floor, floorErr, result)
	}
	if len(result.Checks) != 1 || result.Checks[0].Status != "pass" {
		t.Fatalf("the actual authored workflow result was lost: %#v", result.Checks)
	}
	finished, err := f.e.Store.LatestOperation(ctx, result.RunID, gitOpsModelStep("finish", "model"))
	if err != nil || finished.State != "failed" {
		t.Fatalf("the final fresh byte scan was not recorded as failed: %v %#v", err, finished)
	}
}

func TestGitOpsPhaseObservationRemainsCurrentAfterDependencyReads(t *testing.T) {
	for _, change := range []string{"late-source", "late-expiry"} {
		t.Run(change, func(t *testing.T) {
			f := newGitOpsExecutionFixture(t, false)
			p, err := f.e.GitOpsChecksPlan(context.Background(), f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
			if err != nil || !p.Executable {
				t.Fatalf("baseline phase unavailable: %v %#v", err, p.Findings)
			}
			if change == "late-expiry" {
				p.GitOps.Contract.MaxAgeSeconds = 2
				now := time.Now().Add(-50 * time.Millisecond)
				for _, fields := range [][]string{{"status", "reconciledAt"}, {"status", "operationState", "startedAt"}, {"status", "operationState", "finishedAt"}} {
					profileSet(t, f.application, now.UTC().Format(time.RFC3339Nano), fields...)
				}
				f.seed(t)
			}
			changed := false
			f.kube.PrependReactor("get", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
				if changed || action.(ktesting.GetAction).GetName() != "workflow-token" {
					return false, nil, nil
				}
				changed = true
				if change == "late-source" {
					if err := os.WriteFile(filepath.Join(f.repo.dir, "application.yaml"), []byte("late source drift"), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					time.Sleep(2100 * time.Millisecond)
				}
				return false, nil, nil
			})
			_, err = f.e.inspectGitOpsPlan(context.Background(), p, f.v, f.policy)
			if !changed || err == nil {
				t.Fatalf("phase returned stale controller/source evidence after dependencies: changed=%v error=%v", changed, err)
			}
		})
	}
}
