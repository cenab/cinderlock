package cli_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/spec"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestGitOpsProfileCLIUsesVerifiedRenderAndReadOnlyAPI(t *testing.T) {
	f, sitePath, rendererInput := gitOpsCLIFixture(t)
	objects, err := engine.PermissionObjects(read(t, rendererInput))
	if err != nil {
		t.Fatal(err)
	}
	image := objects[0]["data"].(map[string]any)["image"].(string)
	write(t, rendererInput, []byte(fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: application
  labels: {app: application, app.kubernetes.io/managed-by: Helm}
spec:
  replicas: 1
  selector: {matchLabels: {app: application}}
  template:
    metadata: {labels: {app: application}}
    spec:
      containers:
      - name: application
        image: %s
---
apiVersion: v1
kind: Service
metadata: {name: application}
spec:
  type: ClusterIP
  selector: {app: application}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: configuration}
data: {setting: PRIVATE-CONFIGURATION-SENTINEL}
`, image)))
	repository, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitCommand := func(args ...string) []byte {
		t.Helper()
		base := []string{"--no-pager", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false"}
		command := exec.Command(git, append(base, args...)...)
		command.Dir = repository
		command.Env = []string{"PATH=" + filepath.Dir(git), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "LANG=C", "LC_ALL=C"}
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture Git %v: %v: %s", args, err, body)
		}
		return body
	}
	gitCommand("init", "--initial-branch=fixture")
	write(t, filepath.Join(repository, "application.yaml"), []byte("kind: ConfigMap\nmetadata: {name: previous}\n"))
	gitCommand("add", "--", "application.yaml")
	gitCommand("commit", "-m", "Fixture base")
	f.release.Spec.Deployment.GitOps.Owner = "argocd"
	f.release.Spec.Deployment.GitOps.Revision = strings.TrimSpace(string(gitCommand("rev-parse", "HEAD")))
	f.releasePath, f.lockPath, f.bundlePath = filepath.Join(f.h.dir, "profile-release.json"), filepath.Join(f.h.dir, "profile.lock.json"), filepath.Join(f.h.dir, "profile.cinder")
	if err = spec.Write(f.releasePath, f.release); err != nil {
		t.Fatal(err)
	}
	f.h.ok("release", "lock", f.releasePath, "--out", f.lockPath)
	f.h.ok("bundle", "build", f.lockPath, "--key", f.keyPath, "--key-id", "release", "--out", f.bundlePath)
	manifestPath := filepath.Join(f.h.dir, "profile-desired.yaml")
	f.h.ok("gitops", "export", f.bundlePath, "--site", sitePath, "--out", manifestPath)
	manifest := read(t, manifestPath)
	proposal := decode[engine.GitOpsProposal](t, f.h.ok("gitops", "propose", f.bundlePath, "--site", sitePath, "--repository", repository, "--head", f.release.Spec.Deployment.GitOps.Revision, "--path", "application.yaml", "--manifest", manifestPath, "--approved-manifest-digest", spec.Hash(manifest), "--out", filepath.Join(f.h.dir, "source-proposal.json")))
	if proposal.Source.Patch == "" || proposal.Source.Head != f.release.Spec.Deployment.GitOps.Revision {
		t.Fatal("source proposal did not bind a nonempty change to the signed base")
	}
	patch := filepath.Join(f.h.dir, "disposable-source.patch")
	write(t, patch, []byte(proposal.Source.Patch))
	// Application of this inert proposal is confined to the test-created repository.
	gitCommand("apply", patch)
	gitCommand("add", "--", "application.yaml")
	gitCommand("commit", "-m", "Fixture accepted source")
	revision := strings.TrimSpace(string(gitCommand("rev-parse", "HEAD")))
	if revision == f.release.Spec.Deployment.GitOps.Revision {
		t.Fatal("accepted source did not advance beyond the signed base")
	}
	contract := spec.GitOpsProfileContract{Header: spec.NewHeader("GitOpsProfileContract"), Profile: "argocd-directory-v1", Namespace: "argocd", Name: "application", UID: "controller-uid", Repository: repository, RepositoryURL: "https://git.internal/application.git", AcceptedRevision: revision, ManifestDigest: spec.Hash(manifest), NotBefore: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339Nano), MaxAgeSeconds: 900}
	objects, err = engine.PermissionObjects(manifest)
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]*unstructured.Unstructured{}
	var resources, results []any
	for i, object := range objects {
		body, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{}
		if err = u.UnmarshalJSON(body); err != nil {
			t.Fatal(err)
		}
		u.SetNamespace("test")
		u.SetUID(types.UID(fmt.Sprintf("live-%d", i)))
		u.SetResourceVersion("7")
		u.SetGeneration(1)
		group, version := u.GroupVersionKind().Group, u.GroupVersionKind().Version
		u.SetAnnotations(map[string]string{"argocd.argoproj.io/tracking-id": "application:" + group + "/" + u.GetKind() + ":test/" + u.GetName()})
		fields := map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{"f:argocd.argoproj.io/tracking-id": map[string]any{}}}}
		labels := map[string]any{}
		for name := range u.GetLabels() {
			labels["f:"+name] = map[string]any{}
		}
		if len(labels) != 0 {
			fields["f:metadata"].(map[string]any)["f:labels"] = labels
		}
		switch u.GetKind() {
		case "Deployment":
			fields["f:spec"] = map[string]any{"f:replicas": map[string]any{}, "f:selector": map[string]any{}, "f:template": map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:app": map[string]any{}}}, "f:spec": map[string]any{"f:containers": map[string]any{`k:{"name":"application"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:image": map[string]any{}}}}}}
		case "Service":
			ports, _, _ := unstructured.NestedSlice(u.Object, "spec", "ports")
			ports[0].(map[string]any)["protocol"] = "TCP"
			if err = unstructured.SetNestedSlice(u.Object, ports, "spec", "ports"); err != nil {
				t.Fatal(err)
			}
			fields["f:spec"] = map[string]any{"f:type": map[string]any{}, "f:selector": map[string]any{}, "f:ports": map[string]any{`k:{"port":80,"protocol":"TCP"}`: map[string]any{".": map[string]any{}, "f:port": map[string]any{}, "f:targetPort": map[string]any{}}}}
		case "ConfigMap":
			fields["f:data"] = map[string]any{"f:setting": map[string]any{}}
		}
		entries := []any{map[string]any{"manager": "argocd-controller", "operation": "Apply", "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fields}}
		if u.GetKind() == "Deployment" {
			annotations := u.GetAnnotations()
			annotations["deployment.kubernetes.io/revision"] = "1"
			u.SetAnnotations(annotations)
			entries = append(entries, map[string]any{"manager": "kube-controller-manager", "operation": "Update", "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{".": map[string]any{}, "f:deployment.kubernetes.io/revision": map[string]any{}}}}})
		}
		if err = unstructured.SetNestedSlice(u.Object, entries, "metadata", "managedFields"); err != nil {
			t.Fatal(err)
		}
		if u.GetKind() == "Deployment" {
			u.Object["status"] = map[string]any{"observedGeneration": int64(1), "replicas": int64(1), "updatedReplicas": int64(1), "readyReplicas": int64(1), "availableReplicas": int64(1)}
		}
		identity := map[string]any{"group": group, "version": version, "kind": u.GetKind(), "namespace": "test", "name": u.GetName(), "status": "Synced"}
		if u.GetKind() == "Deployment" {
			identity["health"] = map[string]any{"status": "Healthy"}
		}
		resources = append(resources, identity)
		result := runtime.DeepCopyJSON(identity)
		delete(result, "health")
		result["syncPhase"], result["hookPhase"] = "Sync", "Succeeded"
		results = append(results, result)
		prefix, resource := "/api/v1", ""
		switch u.GetKind() {
		case "Deployment":
			prefix, resource = "/apis/apps/v1", "deployments"
		case "Service":
			resource = "services"
		case "ConfigMap":
			resource = "configmaps"
		}
		live[prefix+"/namespaces/test/"+resource+"/"+u.GetName()] = u
	}
	source := map[string]any{"repoURL": contract.RepositoryURL, "targetRevision": revision, "path": ".", "directory": map[string]any{"include": "application.yaml"}}
	destination := map[string]any{"server": "https://kubernetes.default.svc", "namespace": "test"}
	application := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"namespace": "argocd", "name": "application", "uid": "controller-uid", "resourceVersion": "11", "generation": int64(1)}, "spec": map[string]any{"project": "default", "source": source, "destination": destination, "syncPolicy": map[string]any{"syncOptions": []any{"ServerSideApply=true"}}}, "status": map[string]any{"controllerNamespace": "argocd", "sourceType": "Directory", "sync": map[string]any{"revision": revision, "status": "Synced", "comparedTo": map[string]any{"source": source, "destination": destination}}, "health": map[string]any{"status": "Healthy"}, "resources": resources, "reconciledAt": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), "operationState": map[string]any{"phase": "Succeeded", "startedAt": time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano), "finishedAt": time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano), "operation": map[string]any{"sync": map[string]any{"revision": revision, "syncStrategy": map[string]any{"hook": map[string]any{}}}}, "syncResult": map[string]any{"revision": revision, "source": source, "resources": results}}}}
	var drift atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" {
			t.Errorf("profile attempted mutation %s %s", r.Method, r.URL.Path)
			http.Error(w, "forbidden", 403)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/test" {
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "test", "uid": "namespace-uid"}})
			return
		}
		if r.URL.Path == "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/application" {
			_ = json.NewEncoder(w).Encode(application)
			return
		}
		if object := live[r.URL.Path]; object != nil {
			copy := object.DeepCopy()
			if copy.GetKind() == "ConfigMap" && drift.Load() {
				copy.Object["data"] = map[string]any{"setting": "UNREVIEWED-SENSITIVE-SENTINEL"}
			}
			_ = json.NewEncoder(w).Encode(copy.Object)
			return
		}
		t.Errorf("profile read outside exact scope: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	site := decode[spec.Site](t, read(t, sitePath))
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	write(t, site.Spec.Kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: test\n  cluster:\n    server: "+server.URL+"\n    certificate-authority-data: "+ca+"\ncontexts:\n- name: test\n  context:\n    cluster: test\n    namespace: test\n    user: test\nusers:\n- name: test\n  user:\n    token: synthetic-test-token\ncurrent-context: test\n"))
	contractPath := filepath.Join(f.h.dir, "controller-contract.json")
	if err = spec.Write(contractPath, contract); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.h.dir, "controller-observation.json")
	args := []string{"gitops", "observe-profile", f.bundlePath, "--site", sitePath, "--contract", contractPath, "--manifest", manifestPath, "--out", out}
	index := read(t, filepath.Join(repository, ".git", "index"))
	observed := decode[engine.GitOpsProfileObservation](t, f.h.ok(args...))
	if !observed.Ready || observed.Kind != "GitOpsProfileObservation" || observed.ApplicationAcceptance != "not_established" || observed.AcceptedRevision != revision || observed.NamespaceUID != "namespace-uid" || observed.UID != contract.UID {
		t.Fatal("public route lost exact profile evidence", observed.Findings)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("observation output wasn't private", err)
	}
	if !bytes.Equal(read(t, filepath.Join(repository, "application.yaml")), manifest) || !bytes.Equal(read(t, filepath.Join(repository, ".git", "index")), index) || strings.TrimSpace(string(gitCommand("rev-parse", "HEAD"))) != revision {
		t.Fatal("profile mutated source")
	}
	drift.Store(true)
	args[len(args)-1] = filepath.Join(f.h.dir, "blocked-observation.json")
	blocked := f.h.command(args...)
	if spec.ExitCode(blocked.err) != 10 || decode[engine.GitOpsProfileObservation](t, blocked.result).Ready {
		t.Fatal("controller Healthy concealed live ConfigMap drift", blocked.err)
	}
	for _, artifact := range []string{out, args[len(args)-1]} {
		body := string(read(t, artifact))
		for _, raw := range []string{"PRIVATE-CONFIGURATION-SENTINEL", "UNREVIEWED-SENSITIVE-SENTINEL", contract.RepositoryURL} {
			if strings.Contains(body, raw) {
				t.Fatal("profile artifact leaked private values")
			}
		}
	}
}
