package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	corev1 "k8s.io/api/core/v1"
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

func (f *profileFixture) accepted(t *testing.T, revision string) {
	t.Helper()
	f.repo.head, f.contract.AcceptedRevision = revision, revision
	f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision = revision
	for _, fields := range [][]string{{"spec", "source", "targetRevision"}, {"status", "sync", "revision"}, {"status", "sync", "comparedTo", "source", "targetRevision"}, {"status", "operationState", "operation", "sync", "revision"}, {"status", "operationState", "syncResult", "revision"}, {"status", "operationState", "syncResult", "source", "targetRevision"}} {
		profileSet(t, f.application, revision, fields...)
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
