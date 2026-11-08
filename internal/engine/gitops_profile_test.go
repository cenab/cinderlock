package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type profileFixture struct {
	e           *Engine
	v           *bundle.Verified
	policy      spec.TrustPolicy
	sitePath    string
	contract    spec.GitOpsProfileContract
	manifest    []byte
	repo        proposalRepository
	application *unstructured.Unstructured
	live        []*unstructured.Unstructured
	client      *dynamicfake.FakeDynamicClient
	kube        *fake.Clientset
}

func newProfileFixture(t *testing.T, initOptions ...string) *profileFixture {
	t.Helper()
	stateDir := t.TempDir()
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: filepath.Join(stateDir, "target.kubeconfig"), Context: "fixture", Namespace: "test", NamespaceUID: "namespace-uid", ReleaseName: "app", Profile: "directory-test", Registry: "registry.invalid", StateDir: stateDir, TrustPolicy: filepath.Join(stateDir, "trust.json"), AllowedActions: []string{"gitops-observe"}}}
	site.Metadata.Name = "test"
	kube := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", UID: types.UID("namespace-uid")}})
	e := NewWithClient(site, nil, kube)
	e.Site.Spec.ClusterID = TargetIdentity(e.Kube.Config.Host, "namespace-uid")
	policy := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: "fixture", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Applications: []string{"app"}, Channels: []string{"stable"}}}, AllowedActions: []string{"gitops-observe"}}}
	if err := spec.Write(e.Site.Spec.TrustPolicy, policy); err != nil {
		t.Fatal(err)
	}
	sitePath := filepath.Join(stateDir, "site.json")
	if err := spec.Write(sitePath, e.Site); err != nil {
		t.Fatal(err)
	}
	v := chartFixture(t, e)
	r := &v.Index.Lock.Release
	r.Metadata = spec.Metadata{Application: "app", Version: "2.0.0", Channel: "stable", Sequence: 2}
	r.Spec.Profile = e.Site.Spec.Profile
	r.Spec.Deployment = spec.Deployment{Type: "gitops", Chart: "chart.tgz", GitOps: &spec.GitOps{Owner: "argocd", Path: "application.yaml", Revision: strings.Repeat("a", 40)}}
	r.Spec.Assets = []spec.Asset{{ID: "runner", Type: "image", Source: "registry.invalid/runner:1"}}
	r.Spec.Operations = []spec.Operation{{ID: "sync", Type: "gitops"}}
	r.Spec.Checks = []spec.Check{{ID: "workflow", Type: "http", Domain: "workflow", URL: "http://application/health", ExpectedStatus: 200, Required: true}}
	r.Spec.RequiredChecks = []string{"workflow"}
	r.Spec.Recovery = []spec.Recovery{{ID: "restore", ToRelease: "1.0.0"}}
	r.Spec.Transitions = []spec.Transition{{ID: "upgrade", FromRelease: "1.0.0", Operations: []string{"sync"}, Recovery: "restore"}}
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "runner", Type: "image", Digest: "sha256:" + strings.Repeat("b", 64)})
	v.Digest = "sha256:" + strings.Repeat("c", 64)
	image, err := e.image(v, "runner")
	if err != nil {
		t.Fatal(err)
	}
	template := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels: {app: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: app}}
  template:
    metadata:
      labels: {app: app}
    spec:
      containers:
      - name: app
        image: %s
---
apiVersion: v1
kind: Service
metadata: {name: app}
spec:
  type: ClusterIP
  selector: {app: app}
  ports:
  - port: 80
    targetPort: 8080
---
apiVersion: v1
kind: ConfigMap
metadata: {name: settings}
data: {setting: CONFIGMAP-SENSITIVE-SENTINEL}
`, image)
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "history":
			return nil, errors.New("release: not found")
		case "get":
			return []byte(`{}`), nil
		case "template":
			return []byte(template), nil
		default:
			t.Fatalf("profile invoked Helm writer: %v", args)
			return nil, nil
		}
	}
	manifest, err := e.RenderDesiredState(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	repo := newProposalRepository(t, manifest, initOptions...)
	r.Spec.Deployment.GitOps.Revision = repo.head
	contract := spec.GitOpsProfileContract{Header: spec.NewHeader("GitOpsProfileContract"), Profile: "argocd-directory-v1", Namespace: "argocd", Name: "application", UID: "application-uid", Repository: repo.dir, RepositoryURL: "https://git.example.invalid/team/source.git", AcceptedRevision: repo.head, ManifestDigest: spec.Hash(manifest), NotBefore: time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano), MaxAgeSeconds: 3600}
	objects, err := PermissionObjects(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var live []*unstructured.Unstructured
	var resources, results []any
	for i, raw := range objects {
		body, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{}
		if err = u.UnmarshalJSON(body); err != nil {
			t.Fatal(err)
		}
		u.SetNamespace("test")
		u.SetUID(types.UID(fmt.Sprintf("resource-%d", i)))
		u.SetResourceVersion("7")
		u.SetGeneration(1)
		group := u.GroupVersionKind().Group
		u.SetAnnotations(map[string]string{"argocd.argoproj.io/tracking-id": "application:" + group + "/" + u.GetKind() + ":test/" + u.GetName()})
		fields := map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{"f:argocd.argoproj.io/tracking-id": map[string]any{}}}}
		if len(u.GetLabels()) != 0 {
			fields["f:metadata"].(map[string]any)["f:labels"] = map[string]any{"f:app": map[string]any{}}
		}
		switch u.GetKind() {
		case "Deployment":
			fields["f:spec"] = map[string]any{"f:replicas": map[string]any{}, "f:selector": map[string]any{}, "f:template": map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:app": map[string]any{}}}, "f:spec": map[string]any{"f:containers": map[string]any{`k:{"name":"app"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:image": map[string]any{}}}}}}
		case "Service":
			fields["f:spec"] = map[string]any{"f:type": map[string]any{}, "f:selector": map[string]any{}, "f:ports": map[string]any{`k:{"port":80,"protocol":"TCP"}`: map[string]any{".": map[string]any{}, "f:port": map[string]any{}, "f:targetPort": map[string]any{}}}}
		case "ConfigMap":
			fields["f:data"] = map[string]any{"f:setting": map[string]any{}}
		}
		if err = unstructured.SetNestedSlice(u.Object, []any{map[string]any{"manager": "argocd-controller", "operation": "Apply", "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fields}}, "metadata", "managedFields"); err != nil {
			t.Fatal(err)
		}
		if u.GetKind() == "Deployment" {
			u.Object["status"] = map[string]any{"observedGeneration": int64(1), "replicas": int64(1), "updatedReplicas": int64(1), "readyReplicas": int64(1), "availableReplicas": int64(1)}
		}
		identity := map[string]any{"group": group, "version": u.GroupVersionKind().Version, "kind": u.GetKind(), "namespace": "test", "name": u.GetName(), "status": "Synced"}
		if u.GetKind() == "Deployment" {
			identity["health"] = map[string]any{"status": "Healthy"}
		}
		resources = append(resources, identity)
		result := runtime.DeepCopyJSON(identity)
		delete(result, "health")
		result["syncPhase"], result["hookPhase"] = "Sync", "Succeeded"
		results = append(results, result)
		live = append(live, u)
	}
	source := map[string]any{"repoURL": contract.RepositoryURL, "targetRevision": repo.head, "path": ".", "directory": map[string]any{"include": "application.yaml"}}
	destination := map[string]any{"server": "https://kubernetes.default.svc", "namespace": "test"}
	app := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"namespace": contract.Namespace, "name": contract.Name, "uid": contract.UID, "resourceVersion": "12", "generation": int64(3)}, "spec": map[string]any{"project": "default", "source": source, "destination": destination, "syncPolicy": map[string]any{"syncOptions": []any{"ServerSideApply=true", "FailOnSharedResource=true", "DisableClientSideApplyMigration=true"}}}, "status": map[string]any{"controllerNamespace": contract.Namespace, "sourceType": "Directory", "sync": map[string]any{"revision": repo.head, "status": "Synced", "comparedTo": map[string]any{"source": runtime.DeepCopyJSON(source), "destination": runtime.DeepCopyJSON(destination)}}, "health": map[string]any{"status": "Healthy"}, "reconciledAt": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), "resources": resources, "operationState": map[string]any{"phase": "Succeeded", "startedAt": time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano), "finishedAt": time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano), "operation": map[string]any{"sync": map[string]any{"revision": repo.head}}, "syncResult": map[string]any{"revision": repo.head, "source": runtime.DeepCopyJSON(source), "resources": results}}}}}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	f := &profileFixture{e: e, v: v, policy: policy, sitePath: sitePath, contract: contract, manifest: manifest, repo: repo, application: app, live: live, client: client, kube: kube}
	f.seed(t)
	return f
}

func (f *profileFixture) seed(t *testing.T) {
	t.Helper()
	objects := append([]*unstructured.Unstructured{f.application}, f.live...)
	var seeded []runtime.Object
	for _, u := range objects {
		seeded = append(seeded, u.DeepCopy())
	}
	f.client = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), seeded...)
	f.e.DynamicClient = f.client
	f.kube.ClearActions()
}

func (f *profileFixture) observe() (GitOpsProfileObservation, error) {
	return f.e.ObserveGitOpsProfile(context.Background(), f.v, f.policy, f.sitePath, f.contract, f.manifest)
}

func (f *profileFixture) assertReadOnly(t *testing.T) {
	t.Helper()
	for _, a := range append(f.client.Actions(), f.kube.Actions()...) {
		if a.GetVerb() != "get" {
			t.Fatalf("profile made non-GET call: %s %s", a.GetVerb(), a.GetResource())
		}
		get := a.(ktesting.GetAction)
		key := a.GetResource().Group + "/" + a.GetResource().Version + "/" + a.GetResource().Resource + "/" + a.GetNamespace() + "/" + get.GetName()
		allowed := []string{"argoproj.io/v1alpha1/applications/" + f.contract.Namespace + "/" + f.contract.Name, "apps/v1/deployments/test/app", "/v1/services/test/app", "/v1/configmaps/test/settings", "/v1/namespaces//test"}
		found := false
		for _, expected := range allowed {
			if key == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("GET escaped fixed reviewed inventory: %s", key)
		}
	}
}

func TestObserveGitOpsProfileReady(t *testing.T) {
	f := newProfileFixture(t)
	before := repositoryBytes(t, f.repo.dir)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("ready profile rejected: %v %#v", err, o.Findings)
	}
	if o.ApplicationAcceptance != "not_established" || o.ObservedRevision != f.repo.head || o.RepositoryURLDigest != spec.Hash([]byte(f.contract.RepositoryURL)) || o.ManifestDigest != spec.Hash(f.manifest) || o.TargetID != f.e.Site.Spec.ClusterID {
		t.Fatalf("lost observation bindings: %#v", o)
	}
	if o.ReconciledAt != f.application.Object["status"].(map[string]any)["reconciledAt"] || o.OperationStartedAt == o.ObservedAt || o.OperationFinishedAt == o.ObservedAt {
		t.Fatal("original controller timestamps were replaced")
	}
	if len(o.Resources) != 3 {
		t.Fatalf("missing reviewed resource facts: %#v", o.Resources)
	}
	for _, r := range o.Resources {
		if !r.DesiredFieldsMatch || !r.OwnershipMatch || !r.TrackingMatch || !r.Healthy || r.UID == "" || r.ResourceVersion == "" {
			t.Fatalf("missing live evidence: %#v", r)
		}
	}
	body, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, withheld := range []string{"CONFIGMAP-SENSITIVE-SENTINEL", f.contract.RepositoryURL} {
		if strings.Contains(string(body), withheld) {
			t.Fatal("observation exposed object values or source URL")
		}
	}
	f.assertReadOnly(t)
	if !reflect.DeepEqual(before, repositoryBytes(t, f.repo.dir)) {
		t.Fatal("observation changed local Git repository")
	}
}

func TestObserveGitOpsProfileEmptyHydrationStatus(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.application, map[string]any{}, "status", "sourceHydrator")
	f.seed(t)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("plain Directory Application with empty typed hydration status rejected: %v %#v", err, o.Findings)
	}
	profileSet(t, f.application, map[string]any{"currentOperation": map[string]any{"phase": "Succeeded"}}, "status", "sourceHydrator")
	f.seed(t)
	f.denied(t, "CONTROLLER_MISMATCH")
}

func TestObserveGitOpsProfileDefaultedServiceFieldOwnership(t *testing.T) {
	f := newProfileFixture(t)
	service := f.live[1]
	ports, _, _ := unstructured.NestedSlice(service.Object, "spec", "ports")
	ports[0].(map[string]any)["protocol"] = "TCP"
	profileSet(t, service, ports, "spec", "ports")
	entries, _, _ := unstructured.NestedSlice(service.Object, "metadata", "managedFields")
	entries[0].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"] = map[string]any{
		"f:type": map[string]any{}, "f:selector": map[string]any{},
		"f:ports": map[string]any{`k:{"port":80,"protocol":"TCP"}`: map[string]any{
			".": map[string]any{}, "f:port": map[string]any{}, "f:targetPort": map[string]any{},
		}},
	}
	profileSet(t, service, entries, "metadata", "managedFields")
	f.seed(t)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("Kubernetes defaulted Service SSA list key rejected: %v %#v", err, o.Findings)
	}
}

func TestObserveGitOpsProfileParentMapMembershipDoesNotOwnKeys(t *testing.T) {
	f := newProfileFixture(t)
	entries, _, _ := unstructured.NestedSlice(f.live[2].Object, "metadata", "managedFields")
	entries[0].(map[string]any)["fieldsV1"].(map[string]any)["f:data"] = map[string]any{}
	profileSet(t, f.live[2], entries, "metadata", "managedFields")
	f.seed(t)
	f.denied(t, "OWNERSHIP_MISMATCH")
}

func TestObserveGitOpsProfileHeadlessServiceRequiresReview(t *testing.T) {
	for _, field := range []string{"clusterIP", "clusterIPs"} {
		t.Run(field, func(t *testing.T) {
			f := newProfileFixture(t)
			var value any = "None"
			if field == "clusterIPs" {
				value = []any{"None"}
			}
			profileSet(t, f.live[1], value, "spec", field)
			f.seed(t)
			f.denied(t, "FIELDS_MISMATCH")
		})
	}
	t.Run("explicit-reviewed-headless", func(t *testing.T) {
		f := newProfileFixture(t)
		objects, err := PermissionObjects(f.manifest)
		if err != nil {
			t.Fatal(err)
		}
		objects[1]["spec"].(map[string]any)["clusterIP"] = "None"
		f.reviewObjects(t, objects)
		profileSet(t, f.live[1], []any{"None"}, "spec", "clusterIPs")
		f.seed(t)
		o, err := f.observe()
		if err != nil || !o.Ready {
			t.Fatalf("explicitly reviewed headless Service rejected: %v %#v", err, o.Findings)
		}
	})
}

func TestObserveGitOpsProfileRequiresEffectiveDirectorySource(t *testing.T) {
	f := newProfileFixture(t)
	unstructured.RemoveNestedField(f.application.Object, "status", "sourceType")
	f.seed(t)
	f.denied(t, "CONTROLLER_MISMATCH")
}

func TestObserveGitOpsProfileBindsResolvedSitePathsAndSelectedState(t *testing.T) {
	f := newProfileFixture(t)
	raw := f.e.Site
	raw.Spec.Kubeconfig, raw.Spec.TrustPolicy, raw.Spec.StateDir = "target.kubeconfig", "trust.json", ""
	f.e.Site.Spec.Kubeconfig = filepath.Join(filepath.Dir(f.sitePath), raw.Spec.Kubeconfig)
	body, err := spec.Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.sitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	observed, err := f.observe()
	if err != nil || !observed.Ready {
		t.Fatalf("legitimate Site path resolution/default state was rejected: %v %#v", err, observed.Findings)
	}
	if observed.SourceSiteDigest != spec.Hash(body) {
		t.Fatal("raw Site source identity was lost")
	}
}

func TestObserveGitOpsProfileBlocksActiveHelmWithoutReadingValues(t *testing.T) {
	f := newProfileFixture(t)
	base := f.e.HelmRunner
	valuesRead := false
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "history" {
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		}
		if args[0] == "get" {
			valuesRead = true
			return []byte(`{}`), nil
		}
		return base(ctx, args...)
	}
	f.denied(t, "HELM_OWNER")
	if valuesRead {
		t.Fatal("active Helm values were read before rejecting competing ownership")
	}
}

func TestObserveGitOpsProfileFrozenRenderNeverReadsAppearingHelmValues(t *testing.T) {
	f := newProfileFixture(t)
	base := f.e.HelmRunner
	historyReads, valuesReads := 0, 0
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "history" {
			historyReads++
			if historyReads == 1 {
				return nil, errors.New("release: not found")
			}
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		}
		if args[0] == "get" {
			valuesReads++
			return []byte(`{}`), nil
		}
		return base(ctx, args...)
	}
	f.denied(t, "HELM_CHANGED")
	if historyReads != 2 || valuesReads != 0 {
		t.Fatalf("frozen rendering reopened active release values: history=%d values=%d", historyReads, valuesReads)
	}
}

func TestObserveGitOpsProfileOriginalTimesMustRemainFreshThroughFinalReads(t *testing.T) {
	f := newProfileFixture(t)
	f.contract.MaxAgeSeconds = 2
	var captured *unstructured.Unstructured
	f.client.PrependReactor("get", "applications", func(ktesting.Action) (bool, runtime.Object, error) {
		if captured == nil {
			captured = f.application.DeepCopy()
			for i, field := range []string{"startedAt", "finishedAt"} {
				profileSet(t, captured, time.Now().Add(time.Duration(-100+i*20)*time.Millisecond).UTC().Format(time.RFC3339Nano), "status", "operationState", field)
			}
			profileSet(t, captured, time.Now().Add(-50*time.Millisecond).UTC().Format(time.RFC3339Nano), "status", "reconciledAt")
		}
		return true, captured.DeepCopy(), nil
	})
	namespaceReads := 0
	f.kube.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		namespaceReads++
		if namespaceReads == 2 {
			time.Sleep(3 * time.Second)
		}
		return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", UID: "namespace-uid"}}, nil
	})
	f.denied(t, "STALE")
}

func TestObserveGitOpsProfileAllowsReviewedHelmTemplateLabels(t *testing.T) {
	f := newProfileFixture(t)
	objects, err := PermissionObjects(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	labels := objects[0]["metadata"].(map[string]any)["labels"].(map[string]any)
	labels["app.kubernetes.io/managed-by"], labels["helm.sh/chart"] = "Helm", "application-2.0.0"
	f.reviewObjects(t, objects)
	current := f.live[0].GetLabels()
	current["app.kubernetes.io/managed-by"], current["helm.sh/chart"] = "Helm", "application-2.0.0"
	f.live[0].SetLabels(current)
	f.seed(t)
	observed, err := f.observe()
	if err != nil || !observed.Ready {
		t.Fatalf("reviewed templated labels became an active Helm owner: %v %#v", err, observed.Findings)
	}
}

func TestObserveGitOpsProfileAllowsDefaultHookStrategyWithoutHooks(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.application, map[string]any{"hook": map[string]any{}}, "status", "operationState", "operation", "sync", "syncStrategy")
	f.seed(t)
	observed, err := f.observe()
	if err != nil || !observed.Ready {
		t.Fatalf("known no-hook sync strategy rejected: %v %#v", err, observed.Findings)
	}
}

func TestObserveGitOpsProfileRequiresDeclaredServerSideApply(t *testing.T) {
	f := newProfileFixture(t)
	unstructured.RemoveNestedField(f.application.Object, "spec", "syncPolicy", "syncOptions")
	f.seed(t)
	f.denied(t, "CONTROLLER_MISMATCH")
}

func TestObserveGitOpsProfileRejectsRepositorySourceOverrides(t *testing.T) {
	for _, name := range []string{".argocd-source.yaml", ".argocd-source-application.yaml"} {
		t.Run(name, func(t *testing.T) {
			f := newProfileFixture(t)
			mustWriteProposalFile(t, filepath.Join(f.repo.dir, name), []byte("directory:\n  include: '*.yaml'\n"))
			f.repo.command(nil, "add", "--", name)
			f.repo.command(nil, "commit", "-m", "Fixture source override")
			f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
			f.denied(t, "SOURCE_UNSUPPORTED")
		})
	}
}

func TestObserveGitOpsProfileLiveFieldDrift(t *testing.T) {
	f := newProfileFixture(t)
	containers, _, err := unstructured.NestedSlice(f.live[0].Object, "spec", "template", "spec", "containers")
	if err != nil {
		t.Fatal(err)
	}
	containers[0].(map[string]any)["image"] = "registry.invalid/unreviewed@sha256:" + strings.Repeat("d", 64)
	if err = unstructured.SetNestedSlice(f.live[0].Object, containers, "spec", "template", "spec", "containers"); err != nil {
		t.Fatal(err)
	}
	f.seed(t)
	o, err := f.observe()
	if err != nil || o.Ready || !profileHasBlocker(o, "GITOPS_PROFILE_FIELDS_MISMATCH") {
		t.Fatalf("healthy controller concealed live image drift: err=%v ready=%v findings=%#v", err, o.Ready, o.Findings)
	}
	if len(o.Resources) != 3 || o.Resources[0].DesiredFieldsMatch || !o.Resources[0].Healthy || o.HealthStatus != "Healthy" {
		t.Fatalf("lost independent drift/health facts: %#v", o)
	}
	f.assertReadOnly(t)
}

func profileHasBlocker(o GitOpsProfileObservation, code string) bool {
	for _, finding := range o.Findings {
		if finding.Code == code && finding.Severity == "blocker" {
			return true
		}
	}
	return false
}

func profileSet(t *testing.T, u *unstructured.Unstructured, value any, fields ...string) {
	t.Helper()
	if err := unstructured.SetNestedField(u.Object, value, fields...); err != nil {
		t.Fatal(err)
	}
}

func (f *profileFixture) denied(t *testing.T, code string) GitOpsProfileObservation {
	t.Helper()
	o, err := f.observe()
	if err != nil || o.Ready || !profileHasBlocker(o, "GITOPS_PROFILE_"+code) {
		t.Fatalf("expected %s blocker: err=%v ready=%v findings=%#v", code, err, o.Ready, o.Findings)
	}
	f.assertWithheld(t, o, err)
	f.assertReadOnly(t)
	return o
}

func (f *profileFixture) assertWithheld(t *testing.T, o GitOpsProfileObservation, err error) {
	t.Helper()
	body, marshalErr := json.Marshal(o)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	text := string(body) + fmt.Sprint(err)
	producerURL := "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"
	for _, withheld := range []string{"CONFIGMAP-SENSITIVE-SENTINEL", "PRODUCER-CREDENTIAL-SENTINEL", "RAW-API-SENSITIVE-SENTINEL", "STATUS-SENSITIVE-SENTINEL", f.contract.RepositoryURL, spec.Hash([]byte(producerURL))} {
		if withheld != "" && strings.Contains(text, withheld) {
			t.Fatalf("sensitive producer content escaped in observation/error")
		}
	}
}

func TestObserveGitOpsProfileControllerDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
		value  any
	}{
		{"wrong-uid", []string{"metadata", "uid"}, "other-uid"},
		{"wrong-name", []string{"metadata", "name"}, "other"},
		{"wrong-namespace", []string{"metadata", "namespace"}, "other"},
		{"missing-resource-version", []string{"metadata", "resourceVersion"}, ""},
		{"missing-generation", []string{"metadata", "generation"}, int64(0)},
		{"deleting", []string{"metadata", "deletionTimestamp"}, time.Now().UTC().Format(time.RFC3339)},
		{"pending-operation", []string{"operation"}, map[string]any{"sync": map[string]any{}}},
		{"empty-pending-operation", []string{"operation"}, map[string]any{}},
		{"malformed-empty-conditions", []string{"status", "conditions"}, ""},
		{"malformed-empty-revisions", []string{"status", "sync", "revisions"}, ""},
		{"wrong-reported-source-type", []string{"status", "sourceType"}, "Helm"},
		{"condition", []string{"status", "conditions"}, []any{map[string]any{"type": "ComparisonError", "message": "STATUS-SENSITIVE-SENTINEL"}}},
		{"warning", []string{"status", "warnings"}, []any{"STATUS-SENSITIVE-SENTINEL"}},
		{"wrong-source", []string{"spec", "source", "repoURL"}, "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"},
		{"moving-source-revision", []string{"spec", "source", "targetRevision"}, "main"},
		{"wrong-source-path", []string{"spec", "source", "path"}, "other"},
		{"glob-include", []string{"spec", "source", "directory", "include"}, "*.yaml"},
		{"recursive-directory", []string{"spec", "source", "directory", "recurse"}, true},
		{"excluded-directory", []string{"spec", "source", "directory", "exclude"}, "other.yaml"},
		{"jsonnet", []string{"spec", "source", "directory", "jsonnet"}, map[string]any{}},
		{"unknown-directory-behavior", []string{"spec", "source", "directory", "futureRenderer"}, true},
		{"helm", []string{"spec", "source", "helm"}, map[string]any{}},
		{"kustomize", []string{"spec", "source", "kustomize"}, map[string]any{}},
		{"plugin", []string{"spec", "source", "plugin"}, map[string]any{"name": "custom"}},
		{"chart", []string{"spec", "source", "chart"}, "app"},
		{"ref", []string{"spec", "source", "ref"}, "values"},
		{"multisource", []string{"spec", "sources"}, []any{}},
		{"hydrator", []string{"spec", "sourceHydrator"}, map[string]any{}},
		{"ignore-differences", []string{"spec", "ignoreDifferences"}, []any{}},
		{"remote-destination", []string{"spec", "destination", "server"}, "https://remote.invalid"},
		{"destination-name", []string{"spec", "destination", "name"}, "in-cluster"},
		{"wrong-destination-namespace", []string{"spec", "destination", "namespace"}, "other"},
		{"wrong-compared-source", []string{"status", "sync", "comparedTo", "source", "repoURL"}, "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"},
		{"wrong-compared-destination", []string{"status", "sync", "comparedTo", "destination", "namespace"}, "other"},
		{"compared-multisource", []string{"status", "sync", "comparedTo", "sources"}, []any{}},
		{"compared-ignore-rules", []string{"status", "sync", "comparedTo", "ignoreDifferences"}, []any{}},
		{"wrong-observed-revision", []string{"status", "sync", "revision"}, strings.Repeat("d", 40)},
		{"opaque-observed-revision", []string{"status", "sync", "revision"}, "STATUS-SENSITIVE-SENTINEL"},
		{"not-synced", []string{"status", "sync", "status"}, "OutOfSync"},
		{"unknown-health", []string{"status", "health", "status"}, "STATUS-SENSITIVE-SENTINEL"},
		{"failed-operation", []string{"status", "operationState", "phase"}, "STATUS-SENSITIVE-SENTINEL"},
		{"wrong-operation-revision", []string{"status", "operationState", "syncResult", "revision"}, strings.Repeat("d", 40)},
		{"wrong-operation-source", []string{"status", "operationState", "syncResult", "source", "repoURL"}, "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"},
		{"request-source-override", []string{"status", "operationState", "operation", "sync", "source"}, map[string]any{}},
		{"request-manifest-override", []string{"status", "operationState", "operation", "sync", "manifests"}, []any{"STATUS-SENSITIVE-SENTINEL"}},
		{"selective-sync", []string{"status", "operationState", "operation", "sync", "resources"}, []any{map[string]any{"name": "app"}}},
		{"dry-run-sync", []string{"status", "operationState", "operation", "sync", "dryRun"}, true},
		{"force-apply", []string{"status", "operationState", "operation", "sync", "syncStrategy"}, map[string]any{"apply": map[string]any{"force": true}}},
		{"force-hook-strategy", []string{"status", "operationState", "operation", "sync", "syncStrategy"}, map[string]any{"hook": map[string]any{"force": true}}},
		{"unknown-sync-option", []string{"spec", "syncPolicy", "syncOptions"}, []any{"Validate=false"}},
		{"unsafe-operation-option", []string{"status", "operationState", "operation", "sync", "syncOptions"}, []any{"Replace=true"}},
		{"namespace-creation", []string{"spec", "syncPolicy", "managedNamespaceMetadata"}, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.application, tc.value, tc.fields...)
			f.seed(t)
			if tc.name == "wrong-name" || tc.name == "wrong-namespace" {
				f.client.PrependReactor("get", "applications", func(ktesting.Action) (bool, runtime.Object, error) { return true, f.application.DeepCopy(), nil })
			}
			f.denied(t, "CONTROLLER_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileOriginalTimeDenials(t *testing.T) {
	for _, field := range []string{"reconciledAt", "startedAt", "finishedAt"} {
		for _, problem := range []string{"missing", "malformed", "future", "stale", "before-notBefore"} {
			t.Run(field+"/"+problem, func(t *testing.T) {
				f := newProfileFixture(t)
				fields := []string{"status", "operationState", field}
				if field == "reconciledAt" {
					fields = []string{"status", field}
				}
				value := ""
				switch problem {
				case "malformed":
					value = "STATUS-SENSITIVE-SENTINEL"
				case "future":
					value = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				case "stale":
					value = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
					f.contract.NotBefore = time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano)
				case "before-notBefore":
					value = time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339Nano)
				}
				profileSet(t, f.application, value, fields...)
				f.seed(t)
				f.denied(t, "CONTROLLER_MISMATCH")
			})
		}
	}
	for _, field := range []string{"startedAt", "finishedAt"} {
		t.Run("unordered/"+field, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.application, time.Now().Add(-30*time.Second).UTC().Format(time.RFC3339Nano), "status", "operationState", field)
			f.seed(t)
			f.denied(t, "CONTROLLER_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileInventoryDenials(t *testing.T) {
	for _, operation := range []bool{false, true} {
		for _, problem := range []string{"missing", "extra", "duplicate", "wrong-namespace", "wrong-version", "not-synced", "hook", "phase", "prune-pending", "deletion-confirmation", "nonzero-wave", "deployment-health", "nonworkload-health"} {
			if operation && (problem == "prune-pending" || problem == "deletion-confirmation" || problem == "nonzero-wave" || strings.HasSuffix(problem, "health")) {
				continue
			}
			if !operation && problem == "phase" {
				continue
			}
			t.Run(fmt.Sprintf("operation=%v/%s", operation, problem), func(t *testing.T) {
				f := newProfileFixture(t)
				fields := []string{"status", "resources"}
				if operation {
					fields = []string{"status", "operationState", "syncResult", "resources"}
				}
				resources, _, err := unstructured.NestedSlice(f.application.Object, fields...)
				if err != nil {
					t.Fatal(err)
				}
				first := resources[0].(map[string]any)
				switch problem {
				case "missing":
					resources = resources[:2]
				case "extra":
					extra := runtime.DeepCopyJSON(first)
					extra["name"] = "extra"
					resources = append(resources, extra)
				case "duplicate":
					resources[1] = runtime.DeepCopyJSON(first)
				case "wrong-namespace":
					first["namespace"] = "other"
				case "wrong-version":
					first["version"] = "v1beta1"
				case "not-synced":
					first["status"] = "PruneSkipped"
				case "hook":
					if operation {
						first["hookType"] = "PreSync"
					} else {
						first["hook"] = true
					}
				case "phase":
					first["syncPhase"] = "PostSync"
				case "prune-pending":
					first["requiresPruning"] = true
				case "deletion-confirmation":
					first["requiresDeletionConfirmation"] = true
				case "nonzero-wave":
					first["syncWave"] = int64(1)
				case "deployment-health":
					delete(first, "health")
				case "nonworkload-health":
					resources[1].(map[string]any)["health"] = map[string]any{"status": "STATUS-SENSITIVE-SENTINEL"}
				}
				profileSet(t, f.application, resources, fields...)
				f.seed(t)
				f.denied(t, "INVENTORY_MISMATCH")
			})
		}
	}
	for _, phase := range []string{"Running", "Failed", "STATUS-SENSITIVE-SENTINEL"} {
		t.Run("unresolved-hook-phase/"+phase, func(t *testing.T) {
			f := newProfileFixture(t)
			results, _, _ := unstructured.NestedSlice(f.application.Object, "status", "operationState", "syncResult", "resources")
			results[0].(map[string]any)["hookPhase"] = phase
			profileSet(t, f.application, results, "status", "operationState", "syncResult", "resources")
			f.seed(t)
			f.denied(t, "INVENTORY_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileLiveBehaviorDenials(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		index      int
		fields     []string
		value      any
	}{
		{"deployment-selector-extra", "FIELDS_MISMATCH", 0, []string{"spec", "selector", "matchLabels", "unreviewed"}, "true"},
		{"service-selector-extra", "FIELDS_MISMATCH", 1, []string{"spec", "selector", "unreviewed"}, "true"},
		{"configmap-extra-data", "FIELDS_MISMATCH", 2, []string{"data", "unreviewed"}, "CONFIGMAP-SENSITIVE-SENTINEL"},
		{"configmap-binary-data", "FIELDS_MISMATCH", 2, []string{"binaryData"}, map[string]any{"unreviewed": "c2VjcmV0"}},
		{"opaque-init-container", "RESOURCE_UNHEALTHY", 0, []string{"spec", "template", "spec", "initContainers"}, []any{map[string]any{"name": "unreviewed", "image": "registry.invalid/other"}}},
		{"opaque-ephemeral-container", "RESOURCE_UNHEALTHY", 0, []string{"spec", "template", "spec", "ephemeralContainers"}, []any{map[string]any{"name": "unreviewed", "image": "registry.invalid/other"}}},
		{"deployment-not-rolled-out", "RESOURCE_UNHEALTHY", 0, []string{"status", "availableReplicas"}, int64(0)},
		{"deployment-stale-status", "RESOURCE_UNHEALTHY", 0, []string{"status", "observedGeneration"}, int64(0)},
		{"service-nodeport", "RESOURCE_UNHEALTHY", 1, []string{"spec", "type"}, "NodePort"},
		{"service-load-balancer", "RESOURCE_UNHEALTHY", 1, []string{"spec", "type"}, "LoadBalancer"},
		{"service-external-name", "RESOURCE_UNHEALTHY", 1, []string{"spec", "externalName"}, "outside.invalid"},
		{"service-external-ip", "RESOURCE_UNHEALTHY", 1, []string{"spec", "externalIPs"}, []any{"192.0.2.1"}},
		{"service-lb-class", "RESOURCE_UNHEALTHY", 1, []string{"spec", "loadBalancerClass"}, "external"},
		{"service-healthcheck-route", "RESOURCE_UNHEALTHY", 1, []string{"spec", "healthCheckNodePort"}, int64(32000)},
		{"missing-uid", "RESOURCE_INACTIVE", 0, []string{"metadata", "uid"}, ""},
		{"missing-resource-version", "RESOURCE_INACTIVE", 1, []string{"metadata", "resourceVersion"}, ""},
		{"deleted-resource", "RESOURCE_INACTIVE", 2, []string{"metadata", "deletionTimestamp"}, time.Now().UTC().Format(time.RFC3339)},
		{"malformed-deletion-time", "RESOURCE_INACTIVE", 2, []string{"metadata", "deletionTimestamp"}, "STATUS-SENSITIVE-SENTINEL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.live[tc.index], tc.value, tc.fields...)
			f.seed(t)
			f.denied(t, tc.code)
		})
	}
	for _, behavior := range []string{"lifecycle", "sidecar", "extra-env", "nodeport"} {
		t.Run(behavior, func(t *testing.T) {
			f := newProfileFixture(t)
			u, fields, code := f.live[0], []string{"spec", "template", "spec", "containers"}, "FIELDS_MISMATCH"
			if behavior == "nodeport" {
				u, fields, code = f.live[1], []string{"spec", "ports"}, "RESOURCE_UNHEALTHY"
			}
			items, _, err := unstructured.NestedSlice(u.Object, fields...)
			if err != nil {
				t.Fatal(err)
			}
			switch behavior {
			case "lifecycle":
				items[0].(map[string]any)["lifecycle"] = map[string]any{"postStart": map[string]any{"exec": map[string]any{"command": []any{"unreviewed"}}}}
				code = "RESOURCE_UNHEALTHY"
			case "sidecar":
				items = append(items, map[string]any{"name": "unreviewed", "image": "registry.invalid/sidecar"})
			case "extra-env":
				items[0].(map[string]any)["env"] = []any{map[string]any{"name": "UNREVIEWED", "value": "STATUS-SENSITIVE-SENTINEL"}}
			case "nodeport":
				items[0].(map[string]any)["nodePort"] = int64(32000)
			}
			profileSet(t, u, items, fields...)
			f.seed(t)
			f.denied(t, code)
		})
	}
}

func TestObserveGitOpsProfileKnownAPIDefaults(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.live[0], int64(600), "spec", "progressDeadlineSeconds")
	profileSet(t, f.live[0], int64(10), "spec", "revisionHistoryLimit")
	profileSet(t, f.live[0], map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxSurge": "25%", "maxUnavailable": "25%"}}, "spec", "strategy")
	profileSet(t, f.live[0], "Always", "spec", "template", "spec", "restartPolicy")
	profileSet(t, f.live[0], "ClusterFirst", "spec", "template", "spec", "dnsPolicy")
	profileSet(t, f.live[0], int64(30), "spec", "template", "spec", "terminationGracePeriodSeconds")
	items, _, _ := unstructured.NestedSlice(f.live[0].Object, "spec", "template", "spec", "containers")
	items[0].(map[string]any)["imagePullPolicy"] = "IfNotPresent"
	items[0].(map[string]any)["terminationMessagePath"] = "/dev/termination-log"
	profileSet(t, f.live[0], items, "spec", "template", "spec", "containers")
	profileSet(t, f.live[1], "10.0.0.7", "spec", "clusterIP")
	profileSet(t, f.live[1], []any{"10.0.0.7"}, "spec", "clusterIPs")
	profileSet(t, f.live[1], []any{"IPv4"}, "spec", "ipFamilies")
	profileSet(t, f.live[1], "SingleStack", "spec", "ipFamilyPolicy")
	profileSet(t, f.live[1], "None", "spec", "sessionAffinity")
	f.seed(t)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("known API defaults rejected: %v %#v", err, o.Findings)
	}
	f.assertReadOnly(t)
	f.assertWithheld(t, o, err)
}

func TestObserveGitOpsProfileOwnershipDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
		value  any
	}{
		{"missing-tracking", []string{"metadata", "annotations", "argocd.argoproj.io/tracking-id"}, ""},
		{"wrong-tracking", []string{"metadata", "annotations", "argocd.argoproj.io/tracking-id"}, "other:apps/Deployment:test/app"},
		{"wrong-installation", []string{"metadata", "annotations", "argocd.argoproj.io/installation-id"}, "other"},
		{"argo-label-other-application", []string{"metadata", "labels", "argocd.argoproj.io/instance"}, "other"},
		{"helm-release-annotation", []string{"metadata", "annotations", "meta.helm.sh/release-name"}, "app"},
		{"flux-kustomize", []string{"metadata", "labels", "kustomize.toolkit.fluxcd.io/name"}, "app"},
		{"flux-helm", []string{"metadata", "annotations", "helm.toolkit.fluxcd.io/name"}, "app"},
		{"argo-hook", []string{"metadata", "annotations", "argocd.argoproj.io/hook"}, "Sync"},
		{"argo-ignore", []string{"metadata", "annotations", "argocd.argoproj.io/compare-options"}, "IgnoreExtraneous"},
		{"argo-prune-confirm", []string{"metadata", "annotations", "argocd.argoproj.io/sync-options"}, "Prune=confirm"},
		{"argo-deletion-confirm", []string{"metadata", "annotations", "argocd.argoproj.io/deletion-approved"}, time.Now().UTC().Format(time.RFC3339)},
		{"argo-unknown", []string{"metadata", "annotations", "argocd.argoproj.io/future-behavior"}, "true"},
		{"argo-nonzero-wave", []string{"metadata", "annotations", "argocd.argoproj.io/sync-wave"}, "1"},
		{"other-finalizer", []string{"metadata", "finalizers"}, []any{"other.example/cleanup"}},
		{"other-owner", []string{"metadata", "ownerReferences"}, []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "other", "uid": "other-uid", "controller": true}}},
		{"missing-managed-fields", []string{"metadata", "managedFields"}, []any{}},
		{"malformed-managed-fields", []string{"metadata", "managedFields"}, "STATUS-SENSITIVE-SENTINEL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.live[0], tc.value, tc.fields...)
			f.seed(t)
			f.denied(t, "OWNERSHIP_MISMATCH")
		})
	}
	for _, problem := range []string{"other-manager", "controller-update-without-apply", "competing-spec-writer", "competing-label-writer", "competing-configmap-writer", "incomplete-ownership", "duplicate-manager", "invalid-fieldset", "unknown-mixed-field-path", "wrong-api-version", "wrong-fields-type", "status-claiming-spec"} {
		t.Run(problem, func(t *testing.T) {
			f := newProfileFixture(t)
			u := f.live[0]
			if problem == "competing-configmap-writer" {
				u = f.live[2]
			}
			entries, _, err := unstructured.NestedSlice(u.Object, "metadata", "managedFields")
			if err != nil {
				t.Fatal(err)
			}
			first := entries[0].(map[string]any)
			switch problem {
			case "other-manager":
				first["manager"] = "other-controller"
			case "controller-update-without-apply":
				first["operation"] = "Update"
			case "competing-spec-writer", "competing-label-writer", "competing-configmap-writer", "status-claiming-spec":
				fields := map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}
				if problem == "competing-label-writer" {
					fields = map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:app": map[string]any{}}}}
				}
				if problem == "competing-configmap-writer" {
					fields = map[string]any{"f:data": map[string]any{"f:setting": map[string]any{}}}
				}
				entry := map[string]any{"manager": "other-controller", "operation": "Update", "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fields}
				if problem == "status-claiming-spec" {
					entry["subresource"] = "status"
				}
				entries = append(entries, entry)
			case "incomplete-ownership":
				first["fieldsV1"].(map[string]any)["f:spec"] = map[string]any{"f:replicas": map[string]any{}}
			case "duplicate-manager":
				entries = append(entries, runtime.DeepCopyJSON(first))
			case "invalid-fieldset":
				first["fieldsV1"] = map[string]any{"invalid": map[string]any{}}
			case "unknown-mixed-field-path":
				first["fieldsV1"].(map[string]any)["x:opaque"] = map[string]any{}
			case "wrong-api-version":
				first["apiVersion"] = "apps/v1beta1"
			case "wrong-fields-type":
				first["fieldsType"] = "unknown"
			}
			profileSet(t, u, entries, "metadata", "managedFields")
			f.seed(t)
			f.denied(t, "OWNERSHIP_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileMissingOrDeniedFacts(t *testing.T) {
	for _, resource := range []string{"applications", "deployments", "services", "configmaps", "namespaces"} {
		for _, denied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/denied=%v", resource, denied), func(t *testing.T) {
				f := newProfileFixture(t)
				reactor := func(a ktesting.Action) (bool, runtime.Object, error) {
					name := a.(ktesting.GetAction).GetName()
					gr := a.GetResource().GroupResource()
					if denied {
						return true, nil, apierrors.NewForbidden(gr, name, errors.New("RAW-API-SENSITIVE-SENTINEL"))
					}
					return true, nil, apierrors.NewNotFound(gr, name)
				}
				code := "RESOURCE_UNAVAILABLE"
				if resource == "namespaces" {
					f.kube.PrependReactor("get", resource, reactor)
					code = "TARGET_UNAVAILABLE"
				} else {
					f.client.PrependReactor("get", resource, reactor)
				}
				if resource == "applications" {
					code = "CONTROLLER_UNAVAILABLE"
				}
				f.denied(t, code)
			})
		}
	}
}

func TestObserveGitOpsProfileChangingFacts(t *testing.T) {
	for _, change := range []string{"application-uid", "application-generation", "application-resource-version", "application-spec-without-version-change", "application-denied-on-reread", "site-source", "site-in-memory", "policy-source", "policy-source-bytes-only", "source-file", "namespace-uid", "server"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			code := "CONTROLLER_CHANGED"
			switch change {
			case "site-source", "site-in-memory", "policy-source", "policy-source-bytes-only":
				code = "BINDINGS_CHANGED"
			case "source-file":
				code = "SOURCE_CHANGED"
			case "namespace-uid", "server":
				code = "TARGET_CHANGED"
			}
			f.client.PrependReactor("get", "deployments", func(a ktesting.Action) (bool, runtime.Object, error) {
				switch change {
				case "site-source":
					body, err := os.ReadFile(f.sitePath)
					if err != nil {
						t.Fatal(err)
					}
					mustWriteProposalFile(t, f.sitePath, append(body, '\n'))
				case "site-in-memory":
					f.e.Site.Spec.Namespace = "other"
				case "policy-source":
					p := f.policy
					p.Spec.Epoch++
					body, err := spec.Canonical(p)
					if err != nil {
						t.Fatal(err)
					}
					mustWriteProposalFile(t, f.e.Site.Spec.TrustPolicy, body)
				case "policy-source-bytes-only":
					body, err := os.ReadFile(f.e.Site.Spec.TrustPolicy)
					if err != nil {
						t.Fatal(err)
					}
					mustWriteProposalFile(t, f.e.Site.Spec.TrustPolicy, append(body, '\n'))
				case "source-file":
					mustWriteProposalFile(t, filepath.Join(f.repo.dir, "application.yaml"), []byte("unreviewed: true\n"))
				case "namespace-uid":
					f.kube.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
						return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", UID: "other-uid"}}, nil
					})
				case "server":
					f.e.Kube.Config.Host = "https://other.invalid"
				}
				return false, nil, nil
			})
			reads := 0
			f.client.PrependReactor("get", "applications", func(a ktesting.Action) (bool, runtime.Object, error) {
				reads++
				if reads != 2 {
					return false, nil, nil
				}
				after := f.application.DeepCopy()
				switch change {
				case "application-uid":
					after.SetUID("other-uid")
				case "application-generation":
					after.SetGeneration(after.GetGeneration() + 1)
				case "application-resource-version":
					after.SetResourceVersion("13")
				case "application-spec-without-version-change":
					profileSet(t, after, "other", "spec", "destination", "namespace")
				case "application-denied-on-reread":
					return true, nil, errors.New("RAW-API-SENSITIVE-SENTINEL")
				}
				return true, after, nil
			})
			f.denied(t, code)
		})
	}
}

func TestObserveGitOpsProfileInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		change func(*profileFixture)
	}{
		{"wrong-kind", 2, func(f *profileFixture) { f.contract.Kind = "Other" }},
		{"unsupported-profile", 2, func(f *profileFixture) { f.contract.Profile = "flux-v1" }},
		{"missing-controller-namespace", 2, func(f *profileFixture) { f.contract.Namespace = "" }},
		{"missing-controller-name", 2, func(f *profileFixture) { f.contract.Name = "" }},
		{"missing-controller-uid", 2, func(f *profileFixture) { f.contract.UID = "" }},
		{"missing-local-repository", 2, func(f *profileFixture) { f.contract.Repository = "" }},
		{"credential-url", 2, func(f *profileFixture) {
			f.contract.RepositoryURL = "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"
		}},
		{"url-query", 2, func(f *profileFixture) { f.contract.RepositoryURL += "?token=PRODUCER-CREDENTIAL-SENTINEL" }},
		{"url-fragment", 2, func(f *profileFixture) { f.contract.RepositoryURL += "#PRODUCER-CREDENTIAL-SENTINEL" }},
		{"ssh-url", 2, func(f *profileFixture) { f.contract.RepositoryURL = "ssh://git.example.invalid/source.git" }},
		{"moving-revision", 2, func(f *profileFixture) { f.contract.AcceptedRevision = "main" }},
		{"short-revision", 2, func(f *profileFixture) { f.contract.AcceptedRevision = f.repo.head[:12] }},
		{"upper-case-revision", 2, func(f *profileFixture) { f.contract.AcceptedRevision = strings.Repeat("A", 40) }},
		{"bad-manifest-digest", 2, func(f *profileFixture) { f.contract.ManifestDigest = strings.Repeat("a", 64) }},
		{"wrong-manifest-digest", 2, func(f *profileFixture) { f.contract.ManifestDigest = "sha256:" + strings.Repeat("a", 64) }},
		{"empty-manifest", 2, func(f *profileFixture) { f.manifest = nil }},
		{"missing-notBefore", 2, func(f *profileFixture) { f.contract.NotBefore = "" }},
		{"future-notBefore", 2, func(f *profileFixture) {
			f.contract.NotBefore = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		}},
		{"zero-maxAge", 2, func(f *profileFixture) { f.contract.MaxAgeSeconds = 0 }},
		{"unbounded-maxAge", 2, func(f *profileFixture) { f.contract.MaxAgeSeconds = 86401 }},
		{"invalid-reversion", 2, func(f *profileFixture) {
			f.contract.Reversion = &spec.GitOpsProfileReversion{PreviousRevision: "HEAD", RestoredRevision: f.repo.head}
		}},
		{"flux-release-owner", 10, func(f *profileFixture) { f.v.Index.Lock.Release.Spec.Deployment.GitOps.Owner = "flux" }},
		{"unsigned-path-escape", 10, func(f *profileFixture) { f.v.Index.Lock.Release.Spec.Deployment.GitOps.Path = "../application.yaml" }},
		{"site-profile-mismatch", 10, func(f *profileFixture) { f.e.Site.Spec.Profile = "other" }},
		{"site-capability-denied", 16, func(f *profileFixture) { f.e.Site.Spec.AllowedActions = nil }},
		{"policy-capability-denied", 16, func(f *profileFixture) { f.policy.Spec.AllowedActions = nil }},
		{"state-in-source-repository", 2, func(f *profileFixture) { f.e.StateDir = f.repo.dir }},
		{"render-differs-from-reviewed", 2, func(f *profileFixture) {
			f.manifest = bytes.ReplaceAll(f.manifest, []byte("CONFIGMAP-SENSITIVE-SENTINEL"), []byte("UNREVIEWED-CONFIG-SENTINEL"))
			f.contract.ManifestDigest = spec.Hash(f.manifest)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			tc.change(f)
			o, err := f.observe()
			var typed *spec.Error
			if !errors.As(err, &typed) || spec.ExitCode(err) != tc.code || o.Ready {
				t.Fatalf("invalid input did not fail with typed error %d: %v %#v", tc.code, err, o.Findings)
			}
			f.assertReadOnly(t)
			f.assertWithheld(t, o, err)
		})
	}
	f := newProfileFixture(t)
	body, err := spec.Canonical(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	var parsed spec.GitOpsProfileContract
	if err = spec.Decode(body, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, injected := range []string{`"executable":"unreviewed",`, `"fieldPaths":["status.unreviewed"],`, `"dsl":"unreviewed",`} {
		input := append([]byte("{"+injected), body[1:]...)
		if spec.Decode(input, &parsed) == nil {
			t.Fatal("external JSON accepted a caller-defined adapter")
		}
	}
}

func TestObserveGitOpsProfileInvalidReviewedInventory(t *testing.T) {
	for _, change := range []string{"Secret", "Job", "PersistentVolumeClaim", "other-api-version", "generated-name", "cross-namespace", "hook", "init-container", "ephemeral-container", "lifecycle", "NodePort", "ExternalName", "duplicate", "over-limit", "empty", "status", "malformed-data", "unknown-spec-field"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			objects, err := PermissionObjects(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			first := &unstructured.Unstructured{Object: objects[0]}
			switch change {
			case "Secret", "Job", "PersistentVolumeClaim":
				objects[0]["kind"] = change
			case "other-api-version":
				objects[0]["apiVersion"] = "apps/v1beta1"
			case "generated-name":
				objects[0]["metadata"].(map[string]any)["generateName"] = "app-"
			case "cross-namespace":
				objects[0]["metadata"].(map[string]any)["namespace"] = "other"
			case "hook":
				objects[0]["metadata"].(map[string]any)["annotations"] = map[string]any{"argocd.argoproj.io/hook": "PreSync"}
			case "init-container", "ephemeral-container":
				field := "initContainers"
				if change == "ephemeral-container" {
					field = "ephemeralContainers"
				}
				profileSet(t, first, []any{map[string]any{"name": "unreviewed", "image": "unreviewed"}}, "spec", "template", "spec", field)
			case "lifecycle":
				pod := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				pod["containers"].([]any)[0].(map[string]any)["lifecycle"] = map[string]any{"preStop": map[string]any{"exec": map[string]any{"command": []any{"unreviewed"}}}}
			case "NodePort", "ExternalName":
				objects[1]["spec"].(map[string]any)["type"] = change
			case "duplicate":
				objects = append(objects, objects[0])
			case "over-limit":
				for len(objects) < 65 {
					objects = append(objects, objects[0])
				}
			case "empty":
				objects = nil
			case "status":
				objects[0]["status"] = map[string]any{"replicas": int64(1)}
			case "malformed-data":
				objects[2]["data"].(map[string]any)["setting"] = map[string]any{"opaque": "CONFIGMAP-SENSITIVE-SENTINEL"}
			case "unknown-spec-field":
				objects[0]["spec"].(map[string]any)["unqualifiedBehavior"] = true
			}
			if objects == nil {
				f.manifest = nil
			} else {
				f.manifest, err = encodeObjects(objects)
				if err != nil {
					t.Fatal(err)
				}
			}
			f.contract.ManifestDigest = spec.Hash(f.manifest)
			o, err := f.observe()
			if spec.ExitCode(err) != 2 || o.Ready {
				t.Fatalf("unsupported reviewed inventory admitted: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
			f.assertWithheld(t, o, err)
		})
	}
}

func (f *profileFixture) accepted(t *testing.T, revision string) {
	t.Helper()
	f.repo.head, f.contract.AcceptedRevision = revision, revision
	f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision = revision
	for _, fields := range [][]string{{"spec", "source", "targetRevision"}, {"status", "sync", "revision"}, {"status", "sync", "comparedTo", "source", "targetRevision"}, {"status", "operationState", "operation", "sync", "revision"}, {"status", "operationState", "syncResult", "revision"}, {"status", "operationState", "syncResult", "source", "targetRevision"}} {
		profileSet(t, f.application, revision, fields...)
	}
}

func TestObserveGitOpsProfileLocalSourceDenials(t *testing.T) {
	for _, change := range []string{"dirty-work-file", "dirty-index", "clean-but-unreviewed", "wrong-head", "missing-target"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			file := filepath.Join(f.repo.dir, "application.yaml")
			switch change {
			case "dirty-work-file":
				mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
			case "dirty-index":
				mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
				f.repo.command(nil, "add", "--", "application.yaml")
				mustWriteProposalFile(t, file, f.manifest)
			case "clean-but-unreviewed":
				mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
				f.repo.command(nil, "add", "--", "application.yaml")
				f.repo.command(nil, "commit", "-m", "Fixture unreviewed state")
				f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
			case "wrong-head":
				f.contract.AcceptedRevision = strings.Repeat("f", 40)
			case "missing-target":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			f.seed(t)
			before := repositoryBytes(t, f.repo.dir)
			f.denied(t, "SOURCE_MISMATCH")
			if !reflect.DeepEqual(before, repositoryBytes(t, f.repo.dir)) {
				t.Fatal("denial modified source repository")
			}
		})
	}
}

func TestObserveGitOpsProfileHistoricalFileReversion(t *testing.T) {
	f := newProfileFixture(t)
	restored := f.repo.head
	file := filepath.Join(f.repo.dir, "application.yaml")
	mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
	f.repo.command(nil, "add", "--", "application.yaml")
	f.repo.command(nil, "commit", "-m", "Fixture previous file")
	previous := strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD")))
	mustWriteProposalFile(t, file, f.manifest)
	f.repo.command(nil, "add", "--", "application.yaml")
	f.repo.command(nil, "commit", "-m", "Fixture restored file")
	f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
	f.contract.Reversion = &spec.GitOpsProfileReversion{PreviousRevision: previous, RestoredRevision: restored}
	f.seed(t)
	before := repositoryBytes(t, f.repo.dir)
	o, err := f.observe()
	if err != nil || !o.Ready || o.Reversion == nil {
		t.Fatalf("same-repository file reversion rejected: %v %#v", err, o.Findings)
	}
	if o.Reversion.AcceptedRevision != f.repo.head || o.Reversion.PreviousRevision != previous || o.Reversion.RestoredRevision != restored || o.Reversion.Path != "application.yaml" || o.Reversion.ManifestDigest != spec.Hash(f.manifest) || o.ApplicationAcceptance != "not_established" {
		t.Fatalf("historical file bindings lost: %#v", o.Reversion)
	}
	f.assertReadOnly(t)
	f.assertWithheld(t, o, err)
	if !reflect.DeepEqual(before, repositoryBytes(t, f.repo.dir)) {
		t.Fatal("reversion observation modified source")
	}
	f.contract.Reversion.RestoredRevision = previous
	f.denied(t, "REVERSION_UNAVAILABLE")
	input, err := spec.Canonical(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	input = bytes.Replace(input, []byte(`"previousRevision":`), []byte(`"repository":"/unrelated/repository","previousRevision":`), 1)
	var parsed spec.GitOpsProfileContract
	if spec.Decode(input, &parsed) == nil {
		t.Fatal("reversion accepted an independent repository")
	}
}

func TestObserveGitOpsProfileSupportedBindings(t *testing.T) {
	for _, variant := range []string{"sha256", "installation-id", "nested-file", "granular-managed-fields", "safe-operation-options", "http-url", "nonworkload-health", "withheld-status-messages"} {
		t.Run(variant, func(t *testing.T) {
			var options []string
			if variant == "sha256" {
				options = []string{"--object-format=sha256"}
			}
			f := newProfileFixture(t, options...)
			switch variant {
			case "installation-id":
				f.contract.InstallationID = "installation-one"
				for _, live := range f.live {
					profileSet(t, live, f.contract.InstallationID, "metadata", "annotations", "argocd.argoproj.io/installation-id")
					entries, _, _ := unstructured.NestedSlice(live.Object, "metadata", "managedFields")
					entries[0].(map[string]any)["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any)["f:annotations"].(map[string]any)["f:argocd.argoproj.io/installation-id"] = map[string]any{}
					profileSet(t, live, entries, "metadata", "managedFields")
				}
			case "nested-file":
				if err := os.Mkdir(filepath.Join(f.repo.dir, "manifests"), 0700); err != nil {
					t.Fatal(err)
				}
				f.repo.command(nil, "mv", "application.yaml", "manifests/desired.yml")
				f.repo.command(nil, "commit", "-m", "Fixture nested signed file")
				f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
				f.v.Index.Lock.Release.Spec.Deployment.GitOps.Path = "manifests/desired.yml"
				for _, fields := range [][]string{{"spec", "source"}, {"status", "sync", "comparedTo", "source"}, {"status", "operationState", "syncResult", "source"}} {
					profileSet(t, f.application, "manifests", append(fields, "path")...)
					profileSet(t, f.application, "desired.yml", append(fields, "directory", "include")...)
				}
			case "granular-managed-fields":
				entries, _, _ := unstructured.NestedSlice(f.live[0].Object, "metadata", "managedFields")
				fields := entries[0].(map[string]any)["fieldsV1"].(map[string]any)
				fields["f:spec"] = map[string]any{"f:replicas": map[string]any{}, "f:selector": map[string]any{}, "f:template": map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:app": map[string]any{}}}, "f:spec": map[string]any{"f:containers": map[string]any{`k:{"name":"app"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:image": map[string]any{}}}}}}
				entries = append(entries, map[string]any{"manager": "kube-controller-manager", "operation": "Update", "apiVersion": "apps/v1", "subresource": "status", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:status": map[string]any{}}})
				profileSet(t, f.live[0], "1", "metadata", "annotations", "deployment.kubernetes.io/revision")
				entries = append(entries, map[string]any{"manager": "kube-controller-manager", "operation": "Update", "apiVersion": "apps/v1", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{".": map[string]any{}, "f:deployment.kubernetes.io/revision": map[string]any{}}}}})
				profileSet(t, f.live[0], entries, "metadata", "managedFields")
			case "safe-operation-options":
				profileSet(t, f.application, []any{"ServerSideApply=true", "FailOnSharedResource=true", "DisableClientSideApplyMigration=true"}, "status", "operationState", "operation", "sync", "syncOptions")
				profileSet(t, f.application, map[string]any{"apply": map[string]any{"force": false}}, "status", "operationState", "operation", "sync", "syncStrategy")
			case "http-url":
				f.contract.RepositoryURL = "http://git.example.invalid/source.git"
				for _, fields := range [][]string{{"spec", "source", "repoURL"}, {"status", "sync", "comparedTo", "source", "repoURL"}, {"status", "operationState", "syncResult", "source", "repoURL"}} {
					profileSet(t, f.application, f.contract.RepositoryURL, fields...)
				}
			case "nonworkload-health":
				resources, _, _ := unstructured.NestedSlice(f.application.Object, "status", "resources")
				for _, value := range resources {
					value.(map[string]any)["health"] = map[string]any{"status": "Healthy"}
				}
				profileSet(t, f.application, resources, "status", "resources")
			case "withheld-status-messages":
				profileSet(t, f.application, "STATUS-SENSITIVE-SENTINEL", "status", "health", "message")
				profileSet(t, f.application, "STATUS-SENSITIVE-SENTINEL", "status", "operationState", "message")
			}
			f.seed(t)
			o, err := f.observe()
			if err != nil || !o.Ready || o.ObservedRevision != f.repo.head || o.RepositoryURLDigest != spec.Hash([]byte(f.contract.RepositoryURL)) {
				t.Fatalf("supported binding rejected: %v %#v", err, o.Findings)
			}
			f.assertWithheld(t, o, err)
			f.assertReadOnly(t)
		})
	}
}

func TestObserveGitOpsProfileUnavailableBindings(t *testing.T) {
	for _, change := range []string{"missing-site", "different-site", "missing-policy", "different-policy", "missing-namespace-uid", "wrong-namespace-pin", "wrong-cluster-pin", "nil-kubernetes", "missing-local-repository", "fifo-site", "fifo-policy"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			code := "BINDINGS_UNAVAILABLE"
			switch change {
			case "missing-site":
				if err := os.Remove(f.sitePath); err != nil {
					t.Fatal(err)
				}
			case "different-site":
				site := f.e.Site
				site.Spec.Profile = "other"
				body, err := spec.Canonical(site)
				if err != nil {
					t.Fatal(err)
				}
				mustWriteProposalFile(t, f.sitePath, body)
			case "missing-policy":
				if err := os.Remove(f.e.Site.Spec.TrustPolicy); err != nil {
					t.Fatal(err)
				}
			case "different-policy":
				policy := f.policy
				policy.Spec.Epoch++
				body, err := spec.Canonical(policy)
				if err != nil {
					t.Fatal(err)
				}
				mustWriteProposalFile(t, f.e.Site.Spec.TrustPolicy, body)
			case "missing-namespace-uid":
				f.kube.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test"}}, nil
				})
				code = "TARGET_UNAVAILABLE"
			case "wrong-namespace-pin", "wrong-cluster-pin":
				if change == "wrong-namespace-pin" {
					f.e.Site.Spec.NamespaceUID = "other"
				} else {
					f.e.Site.Spec.ClusterID = "sha256:" + strings.Repeat("0", 64)
				}
				body, err := spec.Canonical(f.e.Site)
				if err != nil {
					t.Fatal(err)
				}
				mustWriteProposalFile(t, f.sitePath, body)
				code = "TARGET_UNAVAILABLE"
			case "nil-kubernetes":
				f.e.Kube = nil
				code = "TARGET_UNAVAILABLE"
			case "missing-local-repository":
				f.contract.Repository = filepath.Join(f.repo.dir, "missing")
				code = "SOURCE_UNAVAILABLE"
			case "fifo-site", "fifo-policy":
				file := f.sitePath
				if change == "fifo-policy" {
					file = f.e.Site.Spec.TrustPolicy
				}
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(file, 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.denied(t, code)
		})
	}
}

func (f *profileFixture) reviewObjects(t *testing.T, objects []map[string]any) {
	t.Helper()
	manifest, err := encodeObjects(objects)
	if err != nil {
		t.Fatal(err)
	}
	f.manifest, f.contract.ManifestDigest = manifest, spec.Hash(manifest)
	originalRunner := f.e.HelmRunner
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "template" {
			return manifest, nil
		}
		return originalRunner(ctx, args...)
	}
	file := f.v.Index.Lock.Release.Spec.Deployment.GitOps.Path
	mustWriteProposalFile(t, filepath.Join(f.repo.dir, file), manifest)
	f.repo.command(nil, "add", "--", file)
	f.repo.command(nil, "commit", "-m", "Fixture reviewed manifest")
	f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
	for i, object := range objects {
		data, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		normalized := &unstructured.Unstructured{}
		if err = normalized.UnmarshalJSON(data); err != nil {
			t.Fatal(err)
		}
		if wanted, exists := normalized.Object["spec"]; exists {
			profileSet(t, f.live[i], wanted, "spec")
		}
		entries, _, _ := unstructured.NestedSlice(f.live[i].Object, "metadata", "managedFields")
		fields := entries[0].(map[string]any)["fieldsV1"].(map[string]any)
		if labels := normalized.GetLabels(); len(labels) != 0 {
			claims := map[string]any{}
			for name := range labels {
				claims["f:"+name] = map[string]any{}
			}
			fields["f:metadata"].(map[string]any)["f:labels"] = claims
		}
		if _, found, _ := unstructured.NestedString(normalized.Object, "spec", "clusterIP"); found {
			fields["f:spec"].(map[string]any)["f:clusterIP"] = map[string]any{}
		}
		profileSet(t, f.live[i], entries, "metadata", "managedFields")
	}
	f.seed(t)
}

func TestObserveGitOpsProfileListsKeepLengthAndOrder(t *testing.T) {
	for _, variant := range []string{"matching", "reordered", "truncated"} {
		t.Run(variant, func(t *testing.T) {
			f := newProfileFixture(t)
			objects, err := PermissionObjects(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			containers := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
			containers[0].(map[string]any)["env"] = []any{map[string]any{"name": "FIRST", "value": "one"}, map[string]any{"name": "SECOND", "value": "two"}}
			f.reviewObjects(t, objects)
			entries, _, _ := unstructured.NestedSlice(f.live[0].Object, "metadata", "managedFields")
			fields := entries[0].(map[string]any)["fieldsV1"].(map[string]any)
			container := fields["f:spec"].(map[string]any)["f:template"].(map[string]any)["f:spec"].(map[string]any)["f:containers"].(map[string]any)[`k:{"name":"app"}`].(map[string]any)
			container["f:env"] = map[string]any{`k:{"name":"FIRST"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:value": map[string]any{}}, `k:{"name":"SECOND"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:value": map[string]any{}}}
			profileSet(t, f.live[0], entries, "metadata", "managedFields")
			f.seed(t)
			if variant != "matching" {
				items, _, _ := unstructured.NestedSlice(f.live[0].Object, "spec", "template", "spec", "containers")
				env := items[0].(map[string]any)["env"].([]any)
				if variant == "reordered" {
					env[0], env[1] = env[1], env[0]
				} else {
					env = env[:1]
				}
				items[0].(map[string]any)["env"] = env
				profileSet(t, f.live[0], items, "spec", "template", "spec", "containers")
				f.seed(t)
				f.denied(t, "FIELDS_MISMATCH")
				return
			}
			o, err := f.observe()
			if err != nil || !o.Ready {
				t.Fatalf("reviewed ordered list rejected: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
		})
	}
}

func TestObserveGitOpsProfileRenderingNeverDiscoversNodes(t *testing.T) {
	for _, nodeName := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit-node=%v", nodeName), func(t *testing.T) {
			f := newProfileFixture(t)
			f.v.Index.Lock.Release.Spec.AIProfile = spec.AIProfile{GPUCount: 1, RuntimeAsset: "runner"}
			f.e.Site.Spec.HardwareEvidence = filepath.Join(f.e.StateDir, "hardware.json")
			if err := spec.Write(f.e.Site.Spec.HardwareEvidence, HardwareEvidence{Header: spec.NewHeader("HardwareEvidence"), NodeName: "gpu-node", GPUs: []GPUFact{{UUID: "GPU-fixture"}}}); err != nil {
				t.Fatal(err)
			}
			site, err := spec.Canonical(f.e.Site)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteProposalFile(t, f.sitePath, site)
			objects, err := PermissionObjects(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			pod := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			pod["containers"].([]any)[0].(map[string]any)["resources"] = map[string]any{"limits": map[string]any{"nvidia.com/gpu": "1"}}
			if nodeName {
				pod["nodeName"] = "gpu-node"
			} else {
				pod["nodeSelector"] = map[string]any{"gpu": "true"}
			}
			f.reviewObjects(t, objects)
			f.kube.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
				t.Fatal("rendering attempted node discovery")
				return true, nil, nil
			})
			_, err = f.observe()
			if spec.ExitCode(err) != 10 {
				t.Fatalf("hardware scope was not rejected: %v", err)
			}
			f.assertReadOnly(t)
		})
	}
}

func TestObserveGitOpsRawArgoCompatibility(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.application, "main", "status", "sync", "revision")
	delete(f.application.Object, "spec")
	f.seed(t)
	o, err := f.e.ObserveGitOps(context.Background(), "argocd", f.contract.Namespace, f.contract.Name, "main", f.policy)
	if err != nil || !o.ControllerReady || o.ObservedRevision != "main" || o.ApplicationAcceptance != "not_tested" {
		t.Fatalf("raw Argo status compatibility changed: %v %#v", err, o)
	}
	f.assertReadOnly(t)
}
