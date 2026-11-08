package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/support"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type testImageRegistry struct {
	sync.Mutex
	objects          map[string][]byte
	media            map[string]string
	uploads          map[string][]byte
	blocked          bool
	serial           int
	mutations        int
	gets             int
	heads            int
	advertisedDigest map[string]string
}

func (r *testImageRegistry) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.Lock()
	defer r.Unlock()
	if request.Method == http.MethodGet {
		r.gets++
	} else if request.Method == http.MethodHead {
		r.heads++
	} else {
		r.mutations++
	}
	if r.blocked {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if request.URL.Path == "/v2/" {
		return
	}
	p := strings.TrimPrefix(request.URL.Path, "/v2/")
	if at := strings.Index(p, "/blobs/uploads/"); at >= 0 {
		if request.Method == http.MethodPost {
			r.serial++
			id := fmt.Sprintf("%s%d", p, r.serial)
			r.uploads[id] = nil
			w.Header().Set("Location", "/v2/"+id)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		data, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil {
			http.Error(w, "fixture read failed", 400)
			return
		}
		r.uploads[p] = append(r.uploads[p], data...)
		if request.Method == http.MethodPatch {
			w.Header().Set("Location", request.URL.Path)
			w.Header().Set("Range", fmt.Sprintf("0-%d", len(r.uploads[p])-1))
			w.WriteHeader(http.StatusAccepted)
			return
		}
		digest := request.URL.Query().Get("digest")
		if request.Method != http.MethodPut || spec.Hash(r.uploads[p]) != digest {
			http.Error(w, "fixture digest mismatch", 400)
			return
		}
		key := p[:at] + "/blobs/" + digest
		r.objects[key] = r.uploads[p]
		delete(r.uploads, p)
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", "/v2/"+key)
		w.WriteHeader(http.StatusCreated)
		return
	}
	if request.Method == http.MethodPut && strings.Contains(p, "/manifests/") {
		data, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil || !strings.HasSuffix(p, spec.Hash(data)) {
			http.Error(w, "fixture manifest mismatch", 400)
			return
		}
		r.objects[p], r.media[p] = data, request.Header.Get("Content-Type")
		w.Header().Set("Docker-Content-Digest", spec.Hash(data))
		w.Header().Set("Location", request.URL.Path)
		w.WriteHeader(http.StatusCreated)
		return
	}
	if data, ok := r.objects[p]; ok && (request.Method == http.MethodGet || request.Method == http.MethodHead) {
		media := r.media[p]
		if media == "" {
			media = "application/octet-stream"
		}
		w.Header().Set("Content-Type", media)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		digest := r.advertisedDigest[p]
		if digest == "" {
			digest = spec.Hash(data)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		if request.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"fixture object absent"}]}`))
}

func stagedImageFixture(t *testing.T) (*Engine, spec.Plan, *bundle.Verified, spec.TrustPolicy, *spec.Authorization, *testImageRegistry) {
	t.Helper()
	ctx := context.Background()
	e, client, policy := fixture(t)
	registry := &testImageRegistry{objects: map[string][]byte{}, media: map[string]string{}, uploads: map[string][]byte{}}
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	e.Site.Spec.Registry = strings.TrimPrefix(server.URL, "http://") + "/offline"
	e.Site.Spec.RegistryPlainHTTP = true
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "registry-http", "gitops-stage")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "registry-http", "gitops-stage")
	policy.Spec.RequireAuthorization = true
	policy.Spec.Epoch++
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"approval"}}}
	admitFixturePolicy(t, e, policy)
	base, verified := fixturePlan(t, e, policy)
	verified.Index.Lock.Release.Spec.Deployment.Type = "gitops"
	verified.Index.Lock.Release.Spec.Deployment.GitOps = &spec.GitOps{Owner: "flux", Path: "application.yaml", Revision: strings.Repeat("a", 40)}
	verified.Root = filepath.Join(e.StateDir, "oci")
	put := func(media string, data []byte) spec.Descriptor {
		digest, n, err := bundle.Store(ctx, verified.Root, bytes.NewReader(data), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return spec.Descriptor{Digest: digest, Size: n, MediaType: media}
	}
	config := put(ociSpec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`))
	layer := put(ociSpec.MediaTypeImageLayer, []byte("synthetic layer; never executed"))
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociSpec.MediaTypeImageManifest, "config": config, "layers": []spec.Descriptor{layer}})
	if err != nil {
		t.Fatal(err)
	}
	root := put(ociSpec.MediaTypeImageManifest, manifest)
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "runner", Type: "image", Source: "registry.invalid/runner:1", Digest: root.Digest, RootDescriptor: &root, Files: []spec.FileRecord{{Path: "config", Digest: config.Digest, Size: config.Size}, {Path: "layer", Digest: layer.Digest, Size: layer.Size}, {Path: "manifest", Digest: root.Digest, Size: root.Size}}}}
	body, err := spec.Canonical(e.Site)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(base.SitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	deployment, err := client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deployment.Labels["kustomize.toolkit.fluxcd.io/name"] = "controller-owned"
	if _, err = client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.HelmRunner = func(context.Context, ...string) ([]byte, error) {
		t.Error("image staging invoked Helm")
		return nil, fmt.Errorf("Helm prohibited")
	}
	p, err := e.ArtifactsPlan(ctx, verified, base.BundlePath, base.SitePath, policy)
	if err != nil || !p.Executable {
		t.Fatalf("artifact plan blocked: %v %#v", err, p.Findings)
	}
	digest, err := spec.Digest(p)
	if err != nil {
		t.Fatal(err)
	}
	a := &spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: digest, PlanKind: p.Kind, TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: p.PolicyEpoch, Actions: []string{"import", "gitops-stage"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: randomID()}
	if err = spec.SignAuthorization(a, private, "customer"); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "deployments" {
			continue
		} // Fixture setup only.
		if action.GetVerb() != "get" && action.GetVerb() != "list" && !(action.GetVerb() == "create" && action.GetResource().Resource == "selfsubjectaccessreviews") {
			t.Fatalf("planning mutated target: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
	client.ClearActions()
	return e, p, verified, policy, a, registry
}

func TestGitOpsArtifactsStageVerifiedGraphWithoutApplicationAcceptance(t *testing.T) {
	e, p, v, policy, a, registry := stagedImageFixture(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, p, v, policy, nil, false); spec.ExitCode(err) != 16 {
		t.Fatal("unsigned staging was admitted", err)
	}
	result, err := e.Apply(ctx, p, v, policy, a, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := e.Site.Spec.Registry + "/runner@" + v.Index.Lock.Assets[0].Digest
	if result.State != "artifacts_staged" || result.Acceptance != "not_established" || result.Domains["workflow"] != "not_tested" || len(result.Checks) != 0 || len(result.Steps) != 1 || result.Steps[0].ExternalID != expected {
		t.Fatalf("image staging misreported acceptance or identity: %#v", result)
	}
	registry.Lock()
	count := len(registry.objects)
	for _, file := range v.Index.Lock.Assets[0].Files {
		kind := "/blobs/"
		if file.Digest == v.Index.Lock.Assets[0].Digest {
			kind = "/manifests/"
		}
		if data := registry.objects["offline/runner"+kind+file.Digest]; spec.Hash(data) != file.Digest {
			t.Errorf("registry object bytes differ: %s", file.Digest)
		}
	}
	registry.Unlock()
	if count != 3 {
		t.Fatalf("actual OCI graph was not uploaded: %d objects", count)
	}
	floor, err := e.Store.ReleaseFloor(ctx, p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
	if err != nil || floor != 0 {
		t.Fatal("image staging advanced accepted release floor", floor, err)
	}
	record, err := e.Store.Run(ctx, result.RunID)
	if err != nil || record.Active {
		t.Fatal("completed stage retained active application claim", err)
	}
	summary := support.Summarize(result)
	if summary.State != "artifacts_staged" || summary.Acceptance != "not_established" {
		t.Fatal(summary)
	}
	for _, action := range e.Kube.Client.(*fake.Clientset).Actions() {
		resource := action.GetResource().Resource
		if resource != "namespaces" && resource != "configmaps" && resource != "leases" {
			t.Fatalf("staging touched application API: %s %s", action.GetVerb(), resource)
		}
	}
	if _, err = e.Apply(ctx, p, v, policy, a, false); spec.ExitCode(err) != 16 {
		t.Fatal("execution authorization replayed", err)
	}
	if _, err = e.Resume(ctx, result.RunID, v, policy, a, false); spec.ExitCode(err) != 10 {
		t.Fatal("terminal artifact stage replayed", err)
	}
	coord, err := e.acquire(ctx, "next-run")
	if err != nil {
		t.Fatal("completed stage blocked later application coordination", err)
	}
	if err = coord.release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGitOpsArtifactsRejectScopeAndCredentialDrift(t *testing.T) {
	e, p, v, policy, a, _ := stagedImageFixture(t)
	for _, change := range []func(*spec.Plan){
		func(p *spec.Plan) { p.Operations[0].Command = []string{"sh", "-c", "mutate"} },
		func(p *spec.Plan) { p.Operations[0].Asset = "" },
		func(p *spec.Plan) { p.Operations[0].Type = "helm" },
		func(p *spec.Plan) { p.Checks = v.Index.Lock.Release.Spec.Checks },
	} {
		data, _ := spec.Canonical(p)
		var altered spec.Plan
		if err := spec.Decode(data, &altered); err != nil {
			t.Fatal(err)
		}
		change(&altered)
		if _, err := e.Apply(context.Background(), altered, v, policy, a, false); spec.ExitCode(err) != 12 {
			t.Fatal("artifact stage accepted broader recipe", err)
		}
	}
	denied := policy
	denied.Spec.AllowedActions = []string{"import", "registry-http"}
	if _, err := e.Apply(context.Background(), p, v, denied, a, false); spec.ExitCode(err) != 16 {
		t.Fatal("missing gitops-stage capability accepted", err)
	}
	e.Site.Spec.Registry = "different.internal/path"
	if _, err := e.Apply(context.Background(), p, v, policy, a, false); spec.ExitCode(err) != 11 {
		t.Fatal("changed registry destination accepted", err)
	}
}

func TestGitOpsArtifactsPlanCannotGrantMissingStageCapability(t *testing.T) {
	e, p, v, policy, _, _ := stagedImageFixture(t)
	e.Site.Spec.AllowedActions = slices.DeleteFunc(e.Site.Spec.AllowedActions, func(action string) bool { return action == "gitops-stage" })
	body, err := spec.Canonical(e.Site)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p.SitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	p.SiteDigest, err = spec.Digest(e.Site)
	if err != nil {
		t.Fatal(err)
	}
	p.SourceSiteDigest = spec.Hash(body)
	if err = e.checkPlan(context.Background(), p, v, policy, true); spec.ExitCode(err) != 16 {
		t.Fatal("import permission granted unadmitted GitOps staging capability", err)
	}
}

func TestGitOpsArtifactsBindOnlyRelevantRegistrySecretData(t *testing.T) {
	e, _, _, _, _, _ := stagedImageFixture(t)
	client := e.Kube.Client
	ctx := context.Background()
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"registry": {Name: "registry-auth", Key: "config"}, "unrelated": {Name: "must-not-read", Key: "other"}}
	e.Site.Spec.RegistryAuthRef = "registry"
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "registry-auth", Namespace: "test", UID: "registry-uid"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"config": []byte(`{"auths":{}}`), "irrelevant": []byte("first")}}
	if _, err := client.CoreV1().Secrets("test").Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	before, err := e.inspectArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secret.Data["irrelevant"] = []byte("changed")
	if _, err = client.CoreV1().Secrets("test").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := e.inspectArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := snapshotDigest(before)
	two, _ := snapshotDigest(after)
	if one != two {
		t.Fatal("irrelevant Secret key invalidated staging")
	}
	secret.Data["config"] = []byte(`{"auths":{"changed":{}}}`)
	if _, err = client.CoreV1().Secrets("test").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err = e.inspectArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	two, _ = snapshotDigest(after)
	if one == two || !strings.HasPrefix(after.Facts[0].Value, "hmac-sha256:") {
		t.Fatal("actual registry credential data was not privately bound")
	}
}

func TestGitOpsArtifactsResumeVerifiesUncertainRegistryGraph(t *testing.T) {
	e, p, v, policy, a, registry := stagedImageFixture(t)
	registry.Lock()
	registry.blocked = true
	registry.Unlock()
	result, err := e.Apply(context.Background(), p, v, policy, a, false)
	if spec.ExitCode(err) != 13 || result.State != "needs_reconciliation" {
		t.Fatal("registry failure lost uncertainty", result, err)
	}
	registry.Lock()
	registry.blocked = false
	registry.Unlock()
	resumed, err := e.Resume(context.Background(), result.RunID, v, policy, a, false)
	if err != nil || resumed.State != "artifacts_staged" || resumed.Acceptance != "not_established" || len(resumed.Steps) != 1 || resumed.Steps[0].ExternalID != e.Site.Spec.Registry+"/runner@"+v.Index.Lock.Assets[0].Digest {
		t.Fatal("uncertain staging did not verify exact graph", resumed, err)
	}
}

func TestGitOpsArtifactsStoppedBeforeImportReleasesActiveRun(t *testing.T) {
	e, p, v, policy, a, _ := stagedImageFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Kube.Client.(*fake.Clientset).PrependReactor("create", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) { cancel(); return false, nil, nil })
	result, err := e.Apply(ctx, p, v, policy, a, false)
	if err == nil || result.State != "artifacts_failed" || result.Acceptance != "not_established" {
		t.Fatal("stopped staging reported application outcome", result, err)
	}
	record, err := e.Store.Run(context.Background(), result.RunID)
	if err != nil || record.Active {
		t.Fatal("definitely stopped staging retained active application claim", err)
	}
	coord, err := e.acquire(context.Background(), "next-run")
	if err != nil {
		t.Fatal("stopped staging blocked later coordination", err)
	}
	if err = coord.release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGitOpsArtifactsBoundImportSelection(t *testing.T) {
	_, _, v, _, _, _ := stagedImageFixture(t)
	first := v.Index.Lock.Assets[0]
	v.Index.Lock.Assets = make([]spec.LockedAsset, 129)
	v.Index.Lock.Release.Spec.Assets = make([]spec.Asset, 129)
	for i := range v.Index.Lock.Assets {
		id := fmt.Sprintf("image-%d", i)
		if i == 0 {
			id = first.ID
		}
		v.Index.Lock.Assets[i] = first
		v.Index.Lock.Assets[i].ID = id
		v.Index.Lock.Release.Spec.Assets[i] = spec.Asset{ID: id, Type: "image", Source: first.Source}
	}
	if _, err := artifactOperations(v); spec.ExitCode(err) != 10 || !strings.Contains(err.Error(), "bounded journal") {
		t.Fatal("unbounded image list did not reach the staging bound", err)
	}
}
