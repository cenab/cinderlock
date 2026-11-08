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
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/engine"
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
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "gitops-stage", "gitops-observe")
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
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: kubeconfig, Context: "test", Namespace: "test", ReleaseName: "application", TrustPolicy: f.policyPath, Profile: "gitops-fixture", Registry: "registry.internal/offline", AllowedActions: []string{"import", "gitops-stage", "gitops-observe"}, HelmPath: helmpath, HelmDigest: spec.Hash(renderer)}}
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

func TestGitOpsProposeCLIRequiresExactReviewedSourceAndManifest(t *testing.T) {
	f, site, _ := gitOpsCLIFixture(t)
	repository, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitRead := func(args ...string) []byte {
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
	gitRead("init", "--initial-branch=fixture")
	base := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: application}\ndata: {state: base}\n")
	write(t, filepath.Join(repository, "application.yaml"), base)
	gitRead("add", "--", "application.yaml")
	gitRead("commit", "-m", "Fixture base")
	head := strings.TrimSpace(string(gitRead("rev-parse", "HEAD")))
	f.release.Spec.Deployment.GitOps.Revision = head
	f.releasePath, f.lockPath, f.bundlePath = filepath.Join(f.h.dir, "proposal-release.json"), filepath.Join(f.h.dir, "proposal.lock.json"), filepath.Join(f.h.dir, "proposal.cinder")
	if err = spec.Write(f.releasePath, f.release); err != nil {
		t.Fatal(err)
	}
	f.h.ok("release", "lock", f.releasePath, "--out", f.lockPath)
	f.h.ok("bundle", "build", f.lockPath, "--key", f.keyPath, "--key-id", "release", "--out", f.bundlePath)
	manifest := filepath.Join(f.h.dir, "reviewed.yaml")
	f.h.ok("gitops", "export", f.bundlePath, "--site", site, "--out", manifest)
	desired := read(t, manifest)
	digest := spec.Hash(desired)
	var verified struct {
		Digest string `json:"digest"`
	}
	if err = json.Unmarshal(f.h.ok("bundle", "verify", f.bundlePath, "--trust", f.policyPath), &verified); err != nil {
		t.Fatal(err)
	}
	indexBefore := read(t, filepath.Join(repository, ".git", "index"))
	out := filepath.Join(f.h.dir, "proposal.json")
	args := []string{"gitops", "propose", f.bundlePath, "--site", site, "--repository", repository, "--head", head, "--path", "application.yaml", "--manifest", manifest, "--approved-manifest-digest", digest, "--out", out}
	proposal := decode[engine.GitOpsProposal](t, f.h.ok(args...))
	var stored engine.GitOpsProposal
	if err = spec.Read(out, &stored); err != nil || !reflect.DeepEqual(proposal, stored) {
		t.Fatal("CLI proposal output differs from its review artifact", err)
	}
	loaded := decode[spec.Site](t, read(t, site))
	loaded.Spec.StateDir = f.h.state
	siteDigest, err := spec.Digest(loaded)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := spec.Digest(decode[spec.TrustPolicy](t, read(t, f.policyPath)))
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Kind != "GitOpsProposal" || proposal.Owner != "flux" || proposal.ApplicationAcceptance != "not_established" || proposal.BundleDigest != verified.Digest || proposal.SiteDigest != siteDigest || proposal.SourceSiteDigest != spec.Hash(read(t, site)) || proposal.PolicyDigest != policyDigest || proposal.Source.Head != head || proposal.Source.Path != "application.yaml" || proposal.Source.ManifestDigest != digest || proposal.Source.BaseDigest != spec.Hash(base) || proposal.Source.Patch == "" {
		t.Fatal("CLI proposal lost signed bundle/Site/source/review bindings", proposal)
	}
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		if !bytes.Equal(read(t, filepath.Join(repository, "application.yaml")), base) || !bytes.Equal(read(t, filepath.Join(repository, ".git", "index")), indexBefore) || strings.TrimSpace(string(gitRead("rev-parse", "HEAD"))) != head {
			t.Fatal("proposal changed repository target/index/HEAD")
		}
	}
	assertUnchanged(t)
	for _, tc := range []struct{ name, flag, value string }{
		{"stale-head", "--head", strings.Repeat("a", 40)},
		{"wrong-path", "--path", "another.yaml"},
		{"wrong-reviewed-digest", "--approved-manifest-digest", spec.Hash([]byte("unreviewed"))},
		{"inside-output", "--out", filepath.Join(repository, "proposal.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := append([]string(nil), args...)
			for i := range attempt {
				if attempt[i] == "--out" {
					attempt[i+1] = filepath.Join(f.h.dir, tc.name+".json")
				}
				if attempt[i] == tc.flag {
					attempt[i+1] = tc.value
				}
			}
			result := f.h.command(attempt...)
			if result.err == nil {
				t.Fatal("unreviewed source/manifest/output admitted")
			}
			assertUnchanged(t)
		})
	}
	t.Run("changed-reviewed-manifest", func(t *testing.T) {
		changed := filepath.Join(f.h.dir, "changed.yaml")
		body := append(append([]byte(nil), desired...), []byte("# unreviewed change\n")...)
		write(t, changed, body)
		attempt := append([]string(nil), args...)
		for i := range attempt {
			switch attempt[i] {
			case "--manifest":
				attempt[i+1] = changed
			case "--approved-manifest-digest":
				attempt[i+1] = spec.Hash(body)
			case "--out":
				attempt[i+1] = filepath.Join(f.h.dir, "changed.json")
			}
		}
		if result := f.h.command(attempt...); spec.ExitCode(result.err) != 11 {
			t.Fatal("manifest no longer matching bundle render admitted", result.err)
		}
		assertUnchanged(t)
	})
	t.Run("inside-state", func(t *testing.T) {
		original := f.h.state
		f.h.state = filepath.Join(repository, "scratch")
		defer func() { f.h.state = original }()
		if result := f.h.command(args...); spec.ExitCode(result.err) != 16 {
			t.Fatal("preparation state inside source admitted", result.err)
		}
		if _, err := os.Stat(f.h.state); !os.IsNotExist(err) {
			t.Fatal("rejected command created state in source", err)
		}
		assertUnchanged(t)
	})
	t.Run("inside-temporary-directory", func(t *testing.T) {
		t.Setenv("TMPDIR", repository)
		if result := f.h.command(args...); spec.ExitCode(result.err) != 16 {
			t.Fatal("verification temporary files inside source admitted", result.err)
		}
		assertUnchanged(t)
	})
}
