package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/catalog"
	"github.com/cenab/cinderlock/internal/cli"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	"github.com/cenab/cinderlock/internal/support"
)

type harness struct {
	t                 *testing.T
	dir, cache, state string
}
type commandResult struct {
	raw, result json.RawMessage
	stderr      string
	err         error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	return &harness{t: t, dir: dir, cache: filepath.Join(dir, "cache"), state: filepath.Join(dir, "state")}
}

func (h *harness) command(args ...string) commandResult {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	flags := []string{"--cache", h.cache, "--state", h.state, "--output", "json", "--no-interactive"}
	err := cli.Execute(context.Background(), append(flags, args...), strings.NewReader(""), &stdout, &stderr)
	out := commandResult{stderr: stderr.String(), err: err}
	if stdout.Len() == 0 {
		return out
	}
	d := json.NewDecoder(&stdout)
	if e := d.Decode(&out.raw); e != nil {
		h.t.Fatalf("%v: invalid JSON output: %v", args, e)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		h.t.Fatalf("%v: multiple outputs or progress mixed with JSON: %v", args, e)
	}
	var envelope struct {
		Kind   string          `json:"kind"`
		Result json.RawMessage `json:"result"`
	}
	if e := json.Unmarshal(out.raw, &envelope); e != nil {
		h.t.Fatal(e)
	}
	if envelope.Kind == "CommandResult" || envelope.Kind == "CommandEvent" {
		out.result = envelope.Result
	} else {
		out.result = out.raw
	}
	return out
}

func (h *harness) ok(args ...string) json.RawMessage {
	h.t.Helper()
	result := h.command(args...)
	if result.err != nil {
		h.t.Fatalf("%v: %v stderr=%s stdout=%s", args, result.err, result.stderr, result.raw)
	}
	if len(result.result) == 0 {
		h.t.Fatalf("%v: no structured result", args)
	}
	return result.result
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var out T
	if err := spec.Decode(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type artifactFixture struct {
	h                                                                  *harness
	release                                                            spec.Release
	releasePath, lockPath, bundlePath, policyPath, keyPath, publicPath string
}

// This fixture exercises artifact delivery only; its HTTP workflow is never run or reported as passing.
func makeArtifactFixture(t *testing.T) artifactFixture {
	t.Helper()
	h := newHarness(t)
	f := artifactFixture{h: h, releasePath: filepath.Join(h.dir, "release.json"), lockPath: filepath.Join(h.dir, "release.lock.json"), bundlePath: filepath.Join(h.dir, "release.cinder"), policyPath: filepath.Join(h.dir, "trust.json"), keyPath: filepath.Join(h.dir, "release.key"), publicPath: filepath.Join(h.dir, "release.pub")}
	h.ok("trust", "keygen", "--private", f.keyPath, "--public", f.publicPath)
	var candidate map[string]any
	if err := json.Unmarshal(h.ok("trust", "init", "--public", f.publicPath, "--application", "cli-fixture", "--out", f.policyPath), &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate["admitted"] != false {
		t.Fatal("candidate trust was presented as admitted")
	}
	h.ok("trust", "validate", f.policyPath)
	write(t, filepath.Join(h.dir, "chart.tgz"), []byte("artifact-only chart transport fixture, not a qualified Helm chart"))
	write(t, filepath.Join(h.dir, "model", "weights.txt"), []byte("synthetic-model-a"))
	write(t, filepath.Join(h.dir, "tokenizer.json"), []byte(`{"revision":"synthetic-v1"}`))
	r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "artifact-unit-test", Deployment: spec.Deployment{Type: "helm", Chart: "chart.tgz"}, Assets: []spec.Asset{{ID: "model", Type: "model-tree", Source: "model", License: "Apache-2.0"}, {ID: "tokenizer", Type: "file", Source: "tokenizer.json", License: "Apache-2.0"}}, AIProfile: spec.AIProfile{ModelAsset: "model", TokenizerAsset: "tokenizer"}, Operations: []spec.Operation{{ID: "deploy", Type: "helm", Idempotent: true}}, Checks: []spec.Check{{ID: "application", Type: "http", Domain: "workflow", Required: true, URL: "http://fixture:8080/health", ExpectedStatus: 200}}, RequiredChecks: []string{"application"}, Transitions: []spec.Transition{{ID: "from-one", FromRelease: "1.0.0", Operations: []string{"deploy"}, Recovery: "previous"}}, Recovery: []spec.Recovery{{ID: "previous", ToRelease: "1.0.0", Operations: []spec.Operation{{ID: "restore-deployment", Type: "helm", Idempotent: true}}}}}}
	r.Metadata = spec.Metadata{Application: "cli-fixture", Version: "2.0.0", Channel: "stable", Sequence: 2}
	f.release = r
	if err := spec.Write(f.releasePath, r); err != nil {
		t.Fatal(err)
	}
	h.ok("release", "validate", f.releasePath)
	h.ok("release", "lock", f.releasePath, "--out", f.lockPath)
	h.ok("bundle", "build", f.lockPath, "--key", f.keyPath, "--key-id", "release", "--out", f.bundlePath)
	return f
}

func TestCLIArtifactReleaseTransportAndGC(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	verified := h.ok("bundle", "verify", f.bundlePath, "--trust", f.policyPath)
	var verification struct {
		Verified    bool   `json:"verified"`
		Digest      string `json:"digest"`
		Payloads    int    `json:"payloads"`
		Application string `json:"application"`
	}
	if err := json.Unmarshal(verified, &verification); err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || !spec.ValidDigest(verification.Digest) || verification.Application != "cli-fixture" {
		t.Fatal(string(verified))
	}
	shown := decode[spec.BundleIndex](t, h.ok("bundle", "show", f.bundlePath, "--trust", f.policyPath))
	if shown.Lock.Release.Metadata.Version != "2.0.0" {
		t.Fatal("wrong signed release")
	}
	inventory := filepath.Join(h.dir, "inventory.json")
	h.ok("release", "inventory", f.lockPath, "--out", inventory)
	extracted := filepath.Join(h.dir, "sbom.json")
	h.ok("bundle", "sbom", f.bundlePath, "--trust", f.policyPath, "--out", extracted)
	var bom struct {
		BOMFormat    string            `json:"bomFormat"`
		Components   []json.RawMessage `json:"components"`
		Compositions []struct {
			Aggregate string `json:"aggregate"`
		} `json:"compositions"`
	}
	if err := json.Unmarshal(read(t, extracted), &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || len(bom.Components) < 3 || len(bom.Compositions) != 1 || bom.Compositions[0].Aggregate != "incomplete" {
		t.Fatal("SBOM omitted components or overstated composition")
	}
	parts := filepath.Join(h.dir, "parts")
	h.ok("bundle", "split", f.bundlePath, "--out", parts, "--part-size", "1024")
	joined := filepath.Join(h.dir, "joined.cinder")
	h.ok("bundle", "join", parts, "--out", joined)
	if !bytes.Equal(read(t, f.bundlePath), read(t, joined)) {
		t.Fatal("multipart changed signed archive bytes")
	}
	h.ok("bundle", "verify", joined, "--trust", f.policyPath)
	r := f.release
	r.Metadata.Version = "3.0.0"
	r.Metadata.Sequence = 3
	write(t, filepath.Join(h.dir, "model", "weights.txt"), []byte("synthetic-model-b"))
	targetRelease := filepath.Join(h.dir, "target.json")
	if err := spec.Write(targetRelease, r); err != nil {
		t.Fatal(err)
	}
	targetLock := filepath.Join(h.dir, "target.lock.json")
	h.ok("release", "lock", targetRelease, "--out", targetLock)
	target := filepath.Join(h.dir, "target.cinder")
	h.ok("bundle", "build", targetLock, "--key", f.keyPath, "--key-id", "release", "--out", target)
	delta := filepath.Join(h.dir, "delta")
	h.ok("bundle", "diff", f.bundlePath, target, "--trust", f.policyPath, "--out", delta)
	reconstructed := filepath.Join(h.dir, "reconstructed.cinder")
	h.ok("bundle", "reconstruct", delta, "--base", f.bundlePath, "--trust", f.policyPath, "--out", reconstructed)
	actual := decode[spec.BundleIndex](t, h.ok("bundle", "show", reconstructed, "--trust", f.policyPath))
	expected := decode[spec.BundleIndex](t, h.ok("bundle", "show", target, "--trust", f.policyPath))
	a, _ := spec.Digest(actual)
	b, _ := spec.Digest(expected)
	if a != b {
		t.Fatal("differential changed signed target identity")
	}
	orphan, _, err := bundle.Store(context.Background(), h.cache, strings.NewReader("unreferenced-cli-test"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	gcPath := filepath.Join(h.dir, "gc.json")
	gc := decode[bundle.GCPlan](t, h.ok("cache", "plan", "--out", gcPath))
	found := false
	for _, d := range gc.Candidates {
		if d.Digest == orphan {
			found = true
		}
	}
	if !found {
		t.Fatal("unreferenced test blob was not planned for GC")
	}
	gcDigest, err := spec.Digest(gc)
	if err != nil {
		t.Fatal(err)
	}
	if result := h.command("cache", "apply", gcPath, "--approved-digest", spec.Hash([]byte("wrong"))); spec.ExitCode(result.err) != 16 {
		t.Fatalf("wrong GC approval accepted: %v", result.err)
	}
	h.ok("cache", "apply", gcPath, "--approved-digest", gcDigest)
	if _, err = os.Stat(filepath.Join(h.cache, "blobs", "sha256", strings.TrimPrefix(orphan, "sha256:"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreferenced blob not deleted", err)
	}
	locked := decode[spec.ReleaseLock](t, read(t, targetLock))
	for _, asset := range locked.Assets {
		for _, file := range asset.Files {
			if _, err = os.Stat(filepath.Join(h.cache, "blobs", "sha256", strings.TrimPrefix(file.Digest, "sha256:"))); err != nil {
				t.Fatalf("GC removed retained asset %s: %v", asset.ID, err)
			}
		}
	}
}

func TestCLIRejectsOverwriteAndTamperedBundle(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	before := read(t, f.keyPath)
	if result := h.command("trust", "keygen", "--private", f.keyPath, "--public", filepath.Join(h.dir, "other.pub")); result.err == nil {
		t.Fatal("existing key overwritten")
	}
	if !bytes.Equal(before, read(t, f.keyPath)) {
		t.Fatal("private key changed on rejected write")
	}
	before = read(t, f.lockPath)
	if result := h.command("release", "lock", f.releasePath, "--out", f.lockPath); result.err == nil {
		t.Fatal("existing lock overwritten")
	}
	if !bytes.Equal(before, read(t, f.lockPath)) {
		t.Fatal("lock changed")
	}
	planPath := filepath.Join(h.dir, "reviewed-plan.json")
	write(t, planPath, []byte("reviewed immutable bytes"))
	if result := h.command("release", "init", "--out", planPath); result.err == nil {
		t.Fatal("reviewed output overwritten")
	}
	if string(read(t, planPath)) != "reviewed immutable bytes" {
		t.Fatal("reviewed bytes changed")
	}
	broken := read(t, f.bundlePath)
	if len(broken) < 1025 {
		t.Fatal("fixture unexpectedly small")
	}
	broken[1024] ^= 0x40
	corrupt := filepath.Join(h.dir, "corrupt.cinder")
	write(t, corrupt, broken)
	if result := h.command("bundle", "verify", corrupt, "--trust", f.policyPath); spec.ExitCode(result.err) != 12 {
		t.Fatalf("corrupt bundle exit=%d err=%v", spec.ExitCode(result.err), result.err)
	}
	policy := decode[spec.TrustPolicy](t, read(t, f.policyPath))
	policy.Spec.Keys[0].Applications = []string{"unrelated"}
	wrong := filepath.Join(h.dir, "wrong-trust.json")
	if err := spec.Write(wrong, policy); err != nil {
		t.Fatal(err)
	}
	if result := h.command("bundle", "verify", f.bundlePath, "--trust", wrong); spec.ExitCode(result.err) != 12 {
		t.Fatal("foreign signer scope accepted", result.err)
	}
}

func TestCLIInputErrorsAndJSONLEnvelope(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"--unknown-flag"}, {"bundle", "verify", "missing.cinder"}, {"release", "init", "unexpected-argument"}, {"--color", "purple", "release", "init"}, {"--timeout", "0s", "release", "init"}, {"not-a-command"}} {
		result := h.command(args...)
		if spec.ExitCode(result.err) != 2 {
			t.Fatalf("%v exit=%d err=%v", args, spec.ExitCode(result.err), result.err)
		}
		if len(result.raw) == 0 {
			t.Errorf("%v: --output json did not produce an error object", args)
		}
	}
	var stdout, stderr bytes.Buffer
	err := cli.Execute(context.Background(), []string{"--cache", h.cache, "--state", h.state, "--output", "jsonl", "release", "init", "--out", filepath.Join(h.dir, "skeleton.json")}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Event      string          `json:"event"`
		Sequence   int             `json:"sequence"`
		Command    string          `json:"command"`
		Result     json.RawMessage `json:"result"`
	}
	if err = json.Unmarshal(stdout.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.APIVersion != spec.APIVersion || event.Kind != "CommandEvent" || event.Event != "result" || event.Sequence != 1 || event.Command != "cinderlock release init" {
		t.Fatal(stdout.String())
	}
}

func TestCLICatalogRejectsInsecureConfigurationAndRemoteBinding(t *testing.T) {
	h := newHarness(t)
	config := filepath.Join(h.dir, "catalog.json")
	cfg := catalog.FileConfig{APIVersion: spec.APIVersion, Kind: "CatalogConfig", Origin: "http://127.0.0.1:8088", Actors: []catalog.Actor{{ID: "operator", TokenHash: catalog.TokenHash("a-long-enough-local-private-token-value"), Projects: map[string][]string{"demo": {"operator"}}}}}
	if err := spec.Write(config, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0644); err != nil {
		t.Fatal(err)
	}
	if result := h.command("catalog", "serve", "--config", config, "--database", filepath.Join(h.dir, "catalog.db")); result.err == nil {
		t.Fatal("world-readable role configuration accepted")
	}
	if result := h.command("catalog", "serve", "--config", config, "--listen", "0.0.0.0:8088"); result.err == nil {
		t.Fatal("remote HTTP binding accepted")
	}
	if result := h.command("catalog", "serve", "--config", config, "--listen", "0.0.0.0:8088", "--allow-remote"); spec.ExitCode(result.err) != 16 {
		t.Fatalf("remote without TLS exit=%d", spec.ExitCode(result.err))
	}
	tokenFile := filepath.Join(h.dir, "catalog.token")
	output := h.ok("catalog", "token", "--out", tokenFile)
	token := strings.TrimSpace(string(read(t, tokenFile)))
	if strings.Contains(string(output), token) {
		t.Fatal("catalog token printed in machine output")
	}
	info, err := os.Stat(tokenFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("token file permissions", err)
	}
}

func TestCLISupportExportPolicyAndSiteBinding(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	policy := decode[spec.TrustPolicy](t, read(t, f.policyPath))
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "support-export")
	policyPath := filepath.Join(h.dir, "export-trust.json")
	if err := spec.Write(policyPath, policy); err != nil {
		t.Fatal(err)
	}
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: filepath.Join(h.dir, "west.kubeconfig"), Context: "west", Namespace: "application", ReleaseName: "qa", TrustPolicy: policyPath, Profile: "unit", NamespaceUID: "namespace-west", ClusterID: "cluster-west", AllowedActions: []string{"support-export"}}}
	site.Metadata.Name = "west"
	sitePath := filepath.Join(h.dir, "west.json")
	if err := spec.Write(sitePath, site); err != nil {
		t.Fatal(err)
	}
	plan := spec.Plan{Header: spec.NewHeader("Plan"), SitePath: sitePath, Snapshot: spec.TargetSnapshot{TargetID: "target-west"}}
	plan.SiteDigest, _ = spec.Digest(site)
	planBytes, _ := spec.Canonical(plan)
	siteBytes, _ := spec.Canonical(site)
	store, err := state.Open(filepath.Join(h.state, "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-local", SiteID: "west", TargetID: "target-west", State: "failed", Acceptance: "fail", Error: "SECRET-MARKER", Checks: []spec.CheckResult{{ID: "application", Domain: "workflow", Required: true, Status: "fail", Reason: "SECRET-MARKER", Evidence: "/private/customer-log"}}, Domains: map[string]string{"integrity": "pass", "workflow": "fail"}}
	if err = store.CreateRun(context.Background(), state.Run{ID: run.RunID, Application: "cli-fixture", Namespace: "application", TargetID: "target-west", PlanDigest: spec.Hash(planBytes), BundleDigest: spec.Hash([]byte("bundle")), State: "verifying", Plan: planBytes, Site: siteBytes}); err != nil {
		t.Fatal(err)
	}
	if err = store.SetState(context.Background(), run.RunID, "failed", false, run); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	status := h.command("run", "status", run.RunID, "--check")
	if spec.ExitCode(status.err) != 15 || len(status.raw) == 0 {
		t.Fatalf("failed status masked: %v", status.err)
	}
	previewPath := filepath.Join(h.dir, "preview.json")
	preview := decode[support.Preview](t, h.ok("support", "export-preview", run.RunID, "--out", previewPath))
	if strings.Contains(string(read(t, previewPath)), "SECRET-MARKER") {
		t.Fatal("preview exposed raw diagnostics")
	}
	denied := site
	denied.Spec.AllowedActions = nil
	deniedPath := filepath.Join(h.dir, "denied-site.json")
	if err = spec.Write(deniedPath, denied); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(h.dir, "export.json")
	if result := h.command("support", "export", previewPath, "--site", deniedPath, "--approved-digest", preview.Digest, "--out", out); spec.ExitCode(result.err) != 16 {
		t.Fatal("site export denial ignored", result.err)
	}
	foreign := site
	foreign.Metadata.Name = "east"
	foreignPath := filepath.Join(h.dir, "foreign-site.json")
	if err = spec.Write(foreignPath, foreign); err != nil {
		t.Fatal(err)
	}
	if result := h.command("support", "export", previewPath, "--site", foreignPath, "--approved-digest", preview.Digest, "--out", out); spec.ExitCode(result.err) != 16 {
		t.Fatal("foreign site exported another site's run", result.err)
	}
	alias := site
	alias.Spec.Context = "other-cluster"
	alias.Spec.NamespaceUID = "namespace-other"
	alias.Spec.ClusterID = "cluster-other"
	alias.Spec.Kubeconfig = filepath.Join(h.dir, "other.kubeconfig")
	aliasPath := filepath.Join(h.dir, "same-name-other-target.json")
	if err = spec.Write(aliasPath, alias); err != nil {
		t.Fatal(err)
	}
	aliasOut := filepath.Join(h.dir, "alias-export.json")
	if result := h.command("support", "export", previewPath, "--site", aliasPath, "--approved-digest", preview.Digest, "--out", aliasOut); spec.ExitCode(result.err) != 16 {
		t.Errorf("same alias/different target exported another site's run: exit=%d err=%v", spec.ExitCode(result.err), result.err)
	}
	h.ok("support", "export", previewPath, "--site", sitePath, "--approved-digest", preview.Digest, "--out", out)
	if strings.Contains(string(read(t, out)), "SECRET-MARKER") || strings.Contains(string(read(t, out)), "customer-log") {
		t.Fatal("export leaked private evidence")
	}
	reportPath := filepath.Join(h.dir, "report.html")
	h.ok("run", "report", run.RunID, "--out", reportPath)
	if !bytes.Contains(read(t, reportPath), []byte("Required workflows")) {
		t.Fatal("report missing workflow section")
	}
	// A human-readable report format cannot replace the global machine-output envelope.
	// Either a structured result or a structured rejection is acceptable without an output path.
	for _, format := range []string{"html", "markdown"} {
		t.Run("machine-output-"+format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"--cache", h.cache, "--state", h.state, "--output", "json", "--no-interactive", "run", "report", run.RunID, "--format", format}
			_ = cli.Execute(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
			d := json.NewDecoder(&stdout)
			var object map[string]json.RawMessage
			if err := d.Decode(&object); err != nil || object == nil {
				t.Fatalf("%s report broke global JSON output: %v", format, err)
			}
			var extra any
			if err := d.Decode(&extra); err != io.EOF {
				t.Fatalf("%s report emitted extra output: %v", format, err)
			}
		})
	}
}
