package cli_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	"github.com/opencontainers/go-digest"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/oci"
)

func gitOpsCLIFixture(t *testing.T) (artifactFixture, string, string) {
	t.Helper()
	h := newHarness(t)
	f := artifactFixture{h: h, keyPath: filepath.Join(h.dir, "producer.key"), publicPath: filepath.Join(h.dir, "producer.pub"), policyPath: filepath.Join(h.dir, "trust.json"), releasePath: filepath.Join(h.dir, "release.json"), lockPath: filepath.Join(h.dir, "release.lock.json"), bundlePath: filepath.Join(h.dir, "release.cinder")}
	h.ok("trust", "keygen", "--private", f.keyPath, "--public", f.publicPath)
	h.ok("trust", "init", "--public", f.publicPath, "--application", "cli-fixture", "--out", f.policyPath)
	policy := decode[spec.TrustPolicy](t, read(t, f.policyPath))
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "gitops-stage")
	body, err := spec.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	write(t, f.policyPath, body)
	layout := filepath.Join(h.dir, "image")
	store, err := oci.New(layout)
	if err != nil {
		t.Fatal(err)
	}
	push := func(media string, data []byte) ociSpec.Descriptor {
		d := ociSpec.Descriptor{MediaType: media, Digest: digest.FromBytes(data), Size: int64(len(data))}
		if err := store.Push(context.Background(), d, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return d
	}
	config := push(ociSpec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`))
	layer := push(ociSpec.MediaTypeImageLayer, []byte("synthetic layer, not executed"))
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociSpec.MediaTypeImageManifest, "config": config, "layers": []ociSpec.Descriptor{layer}})
	if err != nil {
		t.Fatal(err)
	}
	root := push(ociSpec.MediaTypeImageManifest, manifest)
	if err = store.Tag(context.Background(), root, "fixture"); err != nil {
		t.Fatal(err)
	}
	var chart bytes.Buffer
	gz := gzip.NewWriter(&chart)
	tw := tar.NewWriter(gz)
	for name, data := range map[string]string{"chart/Chart.yaml": "apiVersion: v2\nname: fixture\nversion: 2.0.0\nappVersion: 2.0.0\n", "chart/templates/app.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: application\n"} {
		if err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = gz.Close(); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(h.dir, "chart.tgz"), chart.Bytes())
	r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "gitops-fixture", Deployment: spec.Deployment{Type: "gitops", Chart: "chart.tgz", GitOps: &spec.GitOps{Owner: "flux", Revision: strings.Repeat("a", 40), Path: "application.yaml"}}, Assets: []spec.Asset{{ID: "runner", Type: "image", Source: "oci:image#fixture"}}, Operations: []spec.Operation{{ID: "controller", Type: "gitops"}}, Checks: []spec.Check{{ID: "application", Type: "http", Domain: "workflow", Required: true, URL: "http://application/health", ExpectedStatus: 200}}, RequiredChecks: []string{"application"}, Recovery: []spec.Recovery{{ID: "customer-recovery", ToRelease: "1.0.0"}}, Transitions: []spec.Transition{{ID: "upgrade", FromRelease: "1.0.0", Operations: []string{"controller"}, Recovery: "customer-recovery"}}}}
	r.Metadata = spec.Metadata{Application: "cli-fixture", Version: "2.0.0", Channel: "stable", Sequence: 2}
	f.release = r
	if err = spec.Write(f.releasePath, r); err != nil {
		t.Fatal(err)
	}
	h.ok("release", "lock", f.releasePath, "--out", f.lockPath)
	h.ok("bundle", "build", f.lockPath, "--key", f.keyPath, "--key-id", "release", "--out", f.bundlePath)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/test" {
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test","uid":"gitops-namespace"}}`))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			_, _ = w.Write([]byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":true}}`))
			return
		}
		t.Errorf("unexpected target operation %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	kubeconfig := filepath.Join(h.dir, "target.kubeconfig")
	write(t, kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: test\n  cluster:\n    server: "+server.URL+"\n    certificate-authority-data: "+ca+"\ncontexts:\n- name: test\n  context:\n    cluster: test\n    namespace: test\n    user: test\nusers:\n- name: test\n  user:\n    token: synthetic-test-token\ncurrent-context: test\n"))
	desiredPath := filepath.Join(h.dir, "desired.yaml")
	write(t, desiredPath, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: application\ndata:\n  image: registry.internal/offline/runner@"+root.Digest.String()+"\n"))
	helmpath := filepath.Join(h.dir, "fixture-renderer")
	renderer := []byte("#!/bin/sh\ncase \"$1\" in\nhistory) echo 'release: not found' >&2; exit 1;;\ntemplate) /bin/cat '" + desiredPath + "';;\n*) exit 9;;\nesac\n")
	write(t, helmpath, renderer)
	if err = os.Chmod(helmpath, 0700); err != nil {
		t.Fatal(err)
	}
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: kubeconfig, Context: "test", Namespace: "test", ReleaseName: "application", TrustPolicy: f.policyPath, Profile: "gitops-fixture", Registry: "registry.internal/offline", AllowedActions: []string{"import", "gitops-stage"}, HelmPath: helmpath, HelmDigest: spec.Hash(renderer)}}
	site.Metadata.Name = "test"
	sitePath := filepath.Join(h.dir, "site.json")
	if err = spec.Write(sitePath, site); err != nil {
		t.Fatal(err)
	}
	policyDigest, err := spec.Digest(policy)
	if err != nil {
		t.Fatal(err)
	}
	h.ok("trust", "admit-policy", "--site", sitePath, "--approved-digest", policyDigest)
	return f, sitePath, desiredPath
}

func TestGitOpsArtifactsPlanCLIUsesImageOnlyRoute(t *testing.T) {
	f, site, _ := gitOpsCLIFixture(t)
	out := filepath.Join(f.h.dir, "artifacts-plan.json")
	p := decode[spec.Plan](t, f.h.ok("gitops", "artifacts-plan", f.bundlePath, "--site", site, "--out", out))
	if p.Kind != "ArtifactsPlan" || !p.Executable || len(p.Checks) != 0 || len(p.Operations) != 1 || p.Operations[0].Type != "import" || p.Operations[0].Asset != "runner" || p.Snapshot.InstalledVersion != "" {
		t.Fatal("CLI returned application execution scope", p)
	}
	store, err := state.Open(filepath.Join(f.h.state, "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body, err := spec.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := spec.Digest(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CreateRun(context.Background(), state.Run{ID: "status-only-fixture", Application: p.Metadata.Application, Namespace: "test", TargetID: p.Snapshot.TargetID, State: "acquiring", PlanDigest: digest, BundleDigest: p.BundleDigest, Plan: body, Site: read(t, site)}); err != nil {
		t.Fatal(err)
	}
	result := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "status-only-fixture", PlanDigest: digest, BundleDigest: p.BundleDigest, State: "artifacts_staged", Acceptance: "not_established"}
	if err = store.SetState(context.Background(), result.RunID, result.State, false, result); err != nil {
		t.Fatal(err)
	}
	status := f.h.command("run", "status", result.RunID, "--check")
	if spec.ExitCode(status.err) != 10 {
		t.Fatal("staging-only status became application success", status.err)
	}
	observed := decode[state.Run](t, status.result)
	if observed.State != "artifacts_staged" || observed.Active {
		t.Fatal("terminal staging state was lost", observed)
	}
}
