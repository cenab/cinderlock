package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	authorizationv1 "k8s.io/api/authorization/v1"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func fixture(t *testing.T) (*Engine, *fake.Clientset, spec.TrustPolicy) {
	t.Helper()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var n int32 = 1
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", UID: types.UID("namespace-uid")}}, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "test", UID: types.UID("deployment-uid"), Generation: 1, Labels: map[string]string{"app.kubernetes.io/instance": "app"}, Annotations: map[string]string{"meta.helm.sh/release-name": "app"}}, Spec: appsv1.DeploymentSpec{Replicas: &n, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.invalid/app@sha256:" + strings.Repeat("a", 64)}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}})
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	client.PrependReactor("create", "persistentvolumeclaims", func(action ktesting.Action) (bool, runtime.Object, error) {
		claim := action.(ktesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim)
		if claim.UID == "" {
			claim.UID = types.UID("uid-" + claim.Name)
		}
		return false, nil, nil
	})
	client.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		manifest := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap)
		if manifest.UID == "" {
			manifest.UID = types.UID("uid-" + manifest.Name)
		}
		return false, nil, nil
	})
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Namespace: "test", ReleaseName: "app", Registry: "registry.internal/app", StateDir: dir, Profile: "cpu-test", CapacityBytes: 100000, AllowedActions: []string{"job", "migrate", "helm", "restart", "import"}}}
	site.Metadata.Name = "test"
	e := NewWithClient(site, store, client)
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "history" {
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		}
		if args[0] == "get" {
			return []byte(`{"setting":true}`), nil
		}
		return nil, errors.New("unexpected Helm test request")
	}
	policy := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, AllowInteractive: true, AllowedActions: []string{"job", "migrate", "helm", "restart", "import"}}}
	policy.Metadata.Name = "test-policy"
	e.Site.Spec.TrustPolicy = filepath.Join(dir, "trust.json")
	if err := spec.Write(e.Site.Spec.TrustPolicy, policy); err != nil {
		t.Fatal(err)
	}
	admitFixturePolicy(t, e, policy)
	return e, client, policy
}

func admitFixturePolicy(t *testing.T, e *Engine, policy spec.TrustPolicy) {
	t.Helper()
	snapshot, err := e.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := spec.Digest(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Store.ObservePolicyFloor(context.Background(), snapshot.TargetID, policy.Spec.Epoch, digest); err != nil {
		t.Fatal(err)
	}
	body, err := spec.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Site.Spec.TrustPolicy, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func fixturePlan(t *testing.T, e *Engine, policy spec.TrustPolicy) (spec.Plan, *bundle.Verified) {
	t.Helper()
	ctx := context.Background()
	snapshot, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "cpu-test", Operations: []spec.Operation{{ID: "migration", Type: "migrate", Image: "runner", Command: []string{"/bin/true"}, Idempotent: true}}, Checks: []spec.Check{{ID: "inference", Type: "job", Required: true, Image: "runner", Command: []string{"/bin/true"}, Domain: "workflow"}}, RequiredChecks: []string{"inference"}, Transitions: []spec.Transition{{ID: "upgrade", FromRelease: "1.0.0", Operations: []string{"migration"}}}}}
	r.Metadata = spec.Metadata{Application: "app", Version: "2.0.0", Channel: "stable", Sequence: 2}
	r.Spec.Deployment = spec.Deployment{Type: "helm", Chart: "chart.tgz"}
	r.Spec.Assets = []spec.Asset{{ID: "runner", Type: "image", Source: "registry.invalid/runner:1"}}
	r.Spec.Recovery = []spec.Recovery{{ID: "repair", ToRelease: "2.0.0", Operations: []spec.Operation{{ID: "repair", Type: "job", Image: "runner", Command: []string{"/bin/true"}, Idempotent: true}}, Checks: r.Spec.Checks}}
	r.Spec.Transitions[0].Recovery = "repair"
	v := &bundle.Verified{Digest: "sha256:" + strings.Repeat("b", 64), Index: spec.BundleIndex{Lock: spec.ReleaseLock{Release: r, Assets: []spec.LockedAsset{{ID: "runner", Type: "image", Source: "registry.invalid/runner:1", Digest: "sha256:" + strings.Repeat("c", 64)}}}}}
	p := spec.Plan{Header: spec.NewHeader("Plan"), BundlePath: "bundle.cinder", BundleDigest: v.Digest, SitePath: "site.yaml", Snapshot: snapshot, SourceVersion: "1.0.0", TargetVersion: "2.0.0", TransitionID: "upgrade", Operations: r.Spec.Operations, Checks: r.Spec.Checks, RequiredChecks: r.Spec.RequiredChecks, Recovery: r.Spec.Recovery, Executable: true, PolicyEpoch: policy.Spec.Epoch}
	p.Metadata = r.Metadata
	p.SitePath = filepath.Join(e.StateDir, "site.json")
	if _, err := os.Stat(p.SitePath); errors.Is(err, os.ErrNotExist) {
		if err := spec.Write(p.SitePath, e.Site); err != nil {
			t.Fatal(err)
		}
	}
	p.SourceSiteDigest, _ = sourceSiteDigest(p.SitePath)
	p.SiteDigest, _ = spec.Digest(e.Site)
	p.PolicyDigest, _ = spec.Digest(policy)
	p.SnapshotDigest, _ = snapshotDigest(snapshot)
	return p, v
}

func TestInspectionIsReadOnlyAndStatusChurnDoesNotInvalidatePlan(t *testing.T) {
	e, client, _ := fixture(t)
	ctx := context.Background()
	first, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" && a.GetVerb() != "list" {
			t.Fatalf("inspection mutated cluster: %s", a.GetVerb())
		}
	}
	d, _ := client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
	d.Status.AvailableReplicas = 0
	_, _ = client.AppsV1().Deployments("test").UpdateStatus(ctx, d, metav1.UpdateOptions{})
	second, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := snapshotDigest(first)
	b, _ := snapshotDigest(second)
	if a != b {
		t.Fatal("status churn made a semantic plan stale")
	}
}

func TestCheckpointDetectsExternalDriftButAdvancesForOwnRestart(t *testing.T) {
	e, client, policy := fixture(t)
	ctx := context.Background()
	p, _ := fixturePlan(t, e, policy)
	plan, _ := spec.Canonical(p)
	site, _ := spec.Canonical(e.Site)
	if err := e.Store.CreateRun(ctx, state.Run{ID: "run", Application: "app", Namespace: "test", TargetID: p.Snapshot.TargetID, PlanDigest: "plan", Plan: plan, Site: site}); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.SetCheckpoint(ctx, "run", p.SnapshotDigest, p.Snapshot); err != nil {
		t.Fatal(err)
	}
	d, _ := client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
	d.Spec.Template.Spec.Containers[0].Image = "changed"
	_, _ = client.AppsV1().Deployments("test").Update(ctx, d, metav1.UpdateOptions{})
	if _, err := e.currentCheckpoint(ctx, "run", p); spec.ExitCode(err) != 11 {
		t.Fatalf("external drift not rejected: %v", err)
	}
	current, _ := e.Inspect(ctx)
	digest, _ := snapshotDigest(current)
	_ = e.Store.SetCheckpoint(ctx, "run", digest, current)
	d, _ = client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
	_, _ = client.AppsV1().Deployments("test").Update(ctx, RestartSpec(d, "run"), metav1.UpdateOptions{})
	if _, err := e.advanceCheckpoint(ctx, "run", spec.Operation{Type: "restart"}, current); err != nil {
		t.Fatal(err)
	}
	if _, err := e.currentCheckpoint(ctx, "run", p); err != nil {
		t.Fatalf("own confirmed mutation failed to advance checkpoint: %v", err)
	}
}

func TestSignedRecipeBindingRejectsChangedCommandsAndDroppedChecks(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	if err := e.verifyRecipeBinding(p, v); err != nil {
		t.Fatal(err)
	}
	p.Operations = append([]spec.Operation(nil), p.Operations...)
	p.Operations[0].Command = []string{"/bin/false"}
	if err := e.verifyRecipeBinding(p, v); spec.ExitCode(err) != 12 {
		t.Fatalf("tampered operation accepted: %v", err)
	}
	p, v = fixturePlan(t, e, policy)
	p.RequiredChecks = []string{}
	if err := e.verifyRecipeBinding(p, v); spec.ExitCode(err) != 12 {
		t.Fatalf("removed checks accepted: %v", err)
	}
}

func TestAuthorizationRequiresSeparateApprovalRoleAndExactPlan(t *testing.T) {
	e, _, policy := fixture(t)
	p, _ := fixturePlan(t, e, policy)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"release"}}}
	p.PolicyDigest, _ = spec.Digest(policy)
	digest, _ := spec.Digest(p)
	a := spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: digest, PlanKind: "Plan", TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: 1, Actions: []string{"migrate"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: "unique"}
	if err := spec.SignAuthorization(&a, private, "customer"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.authorize(p, policy, &a, false); spec.ExitCode(err) != 16 {
		t.Fatalf("release key was accepted as customer approval: %v", err)
	}
	policy.Spec.Keys[0].Roles = []string{"approval"}
	p.PolicyDigest, _ = spec.Digest(policy)
	a.PolicyDigest = p.PolicyDigest
	a.PlanDigest, _ = spec.Digest(p)
	_ = spec.SignAuthorization(&a, private, "customer")
	if _, err := e.authorize(p, policy, &a, false); err != nil {
		t.Fatal(err)
	}
	a.TargetID = "another-target"
	_ = spec.SignAuthorization(&a, private, "customer")
	if _, err := e.authorize(p, policy, &a, false); spec.ExitCode(err) != 16 {
		t.Fatalf("wrong target authorization accepted: %v", err)
	}
}

func TestExpiredLeaseDoesNotAuthorizeTakeover(t *testing.T) {
	e, client, _ := fixture(t)
	ctx := context.Background()
	holder := "old-worker"
	duration := int32(1)
	old := metav1.NewMicroTime(time.Now().Add(-time.Hour))
	name := "cinderlock-" + fingerprint("app")[7:27]
	_, err := client.CoordinationV1().Leases("test").Create(ctx, &coordv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test"}, Spec: coordv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &old}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.acquire(ctx, "new-run"); spec.ExitCode(err) != 18 {
		t.Fatalf("expired lease taken over: %v", err)
	}
}

func TestMissingMigrationResultDoesNotStartDuplicate(t *testing.T) {
	e, client, policy := fixture(t)
	ctx := context.Background()
	p, v := fixturePlan(t, e, policy)
	p.Operations[0].Idempotent = false
	p.Operations[0].ReconcileCommand = []string{"/bin/check-ledger"}
	v.Index.Lock.Release.Spec.Operations = p.Operations
	digest, _ := spec.Digest(p)
	plan, _ := spec.Canonical(p)
	site, _ := spec.Canonical(e.Site)
	if err := e.Store.CreateRun(ctx, state.Run{ID: "resume", Application: "app", Namespace: "test", TargetID: p.Snapshot.TargetID, PlanDigest: digest, BundleDigest: v.Digest, State: "needs_reconciliation", Plan: plan, Site: site}); err != nil {
		t.Fatal(err)
	}
	intent := p.Operations[0]
	intent.ReconcileCommand = nil
	if _, err := e.Store.Intent(ctx, "resume", "migration", intent, "missing-job"); err != nil {
		t.Fatal(err)
	}
	if err := e.clusterRecord(ctx, "resume", digest, "needs_reconciliation", nil); err != nil {
		t.Fatal(err)
	}
	_, err := e.Resume(ctx, "resume", v, policy, nil, true)
	if spec.ExitCode(err) != 13 {
		t.Fatalf("expected uncertainty, got %v", err)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "jobs" {
			t.Fatal("duplicate migration Job created")
		}
	}
}

func TestKubeconfigRejectsCredentialExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	body := `apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: https://127.0.0.1:1234
contexts:
- name: explicit
  context:
    cluster: cluster
    user: user
users:
- name: user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/sh
      args: [-c, touch /tmp/cinderlock-must-not-execute]
      interactiveMode: Never
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewKubernetes(path, "explicit", "test", "app")
	if err == nil || !strings.Contains(err.Error(), "plugins") {
		t.Fatalf("credential exec accepted: %v", err)
	}
}

func TestUnknownOperationEvidenceRemainsPrivateJSON(t *testing.T) {
	e, _, _ := fixture(t)
	ctx := context.Background()
	r := state.Run{ID: "evidence", Application: "app", Namespace: "test", TargetID: "target", PlanDigest: "plan", Plan: json.RawMessage(`{}`), Site: json.RawMessage(`{}`)}
	if err := e.Store.CreateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Store.Intent(ctx, "evidence", "step", map[string]string{"id": "step"}, "job/step"); err != nil {
		t.Fatal(err)
	}
	ops, err := e.Store.Operations(ctx, "evidence")
	if err != nil || len(ops) != 1 || ops[0].State != "intent" {
		t.Fatalf("intent lost: %#v %v", ops, err)
	}
}

func TestSafeBoundaryRereadsTrustPolicyAndSourceSite(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	ctx := context.Background()
	if err := e.checkPlan(ctx, p, v, policy, false); err != nil {
		t.Fatal(err)
	}
	changed := policy
	changed.Spec.Epoch++
	body, _ := spec.Canonical(changed)
	if err := os.WriteFile(e.Site.Spec.TrustPolicy, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.checkPlan(ctx, p, v, policy, false); spec.ExitCode(err) != 11 {
		t.Fatalf("current policy revocation ignored: %v", err)
	}
	body, _ = spec.Canonical(policy)
	if err := os.WriteFile(e.Site.Spec.TrustPolicy, body, 0600); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(p.SitePath)
	body = append(body, '\n')
	if err := os.WriteFile(p.SitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.checkPlan(ctx, p, v, policy, false); spec.ExitCode(err) != 11 {
		t.Fatalf("source Site edit ignored: %v", err)
	}
}

func TestPlanBlocksUnreadableRequiredSecrets(t *testing.T) {
	e, _, policy := fixture(t)
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"needed": {Name: "absent", Key: "token"}}
	p, v := fixturePlan(t, e, policy)
	v.Index.Lock.Release.Spec.Operations[0].SecretRefs = []string{"needed"}
	v.Index.Lock.Release.Spec.Checks[0].SecretRefs = []string{"needed"}
	plan, err := e.Plan(context.Background(), v, p.BundlePath, p.SitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable {
		t.Fatal("unavailable secret accepted")
	}
	found := false
	for _, finding := range plan.Findings {
		if finding.Code == "SECRET_ABSENT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing actionable secret finding: %#v", plan.Findings)
	}
}

func TestDeploymentRolloutRejectsOldGenerationAndOldReplica(t *testing.T) {
	desired := int32(1)
	complete := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Spec: appsv1.DeploymentSpec{Replicas: &desired}, Status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}}
	if !deploymentRolledOut(&complete) {
		t.Fatal("complete control was not rolled out")
	}
	for _, change := range []func(*appsv1.Deployment){func(d *appsv1.Deployment) { d.Status.ObservedGeneration = 1 }, func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 0 }, func(d *appsv1.Deployment) { d.Status.Replicas = 2 }, func(d *appsv1.Deployment) { n := int32(1); d.Status.TerminatingReplicas = &n }} {
		d := complete.DeepCopy()
		change(d)
		if deploymentRolledOut(d) {
			t.Fatal("incomplete rollout accepted")
		}
	}
}

func TestRestartVerificationWaitsUntilOnlyNewReadyPodsRemain(t *testing.T) {
	e, client, _ := fixture(t)
	ctx := context.Background()
	d, err := client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	d.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/instance": "app"}}
	d = RestartSpec(d, "new-run")
	if _, err := client.AppsV1().Deployments("test").Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "test", Labels: map[string]string{"app.kubernetes.io/instance": "app"}, Annotations: map[string]string{"cinderlock.dev/restart-run": "old-run"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if _, err := client.CoreV1().Pods("test").Create(ctx, old, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if err := e.waitDeployment(short, "app", 1, "new-run", string(d.UID)); err == nil {
		t.Fatal("old pod could satisfy restart acceptance")
	}
	if err := client.CoreV1().Pods("test").Delete(ctx, "old", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	fresh := old.DeepCopy()
	fresh.Name = "new"
	fresh.Annotations["cinderlock.dev/restart-run"] = "new-run"
	if _, err := client.CoreV1().Pods("test").Create(ctx, fresh, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.waitDeployment(ctx, "app", 1, "new-run", string(d.UID)); err != nil {
		t.Fatal(err)
	}
}
