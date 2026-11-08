package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func checkScript(id string) *spec.ScriptContract {
	return &spec.ScriptContract{Inputs: []string{"locked runner image and explicit check argv"}, Permissions: []string{"synthetic application check; no Kubernetes API token"}, SideEffects: []string{"declared synthetic application probe"}, SuccessChecks: []string{id}, Retry: "manual"}
}

func TestSourceAuthMustRemainOutsideRelease(t *testing.T) {
	h := newHarness(t)
	var release spec.Release
	h.ok("release", "init", "--out", filepath.Join(h.dir, "release.json"))
	if err := spec.Read(filepath.Join(h.dir, "release.json"), &release); err != nil {
		t.Fatal(err)
	}
	// A complete release is needed to reach source admission.
	release.Spec.Checks = []spec.Check{{ID: "application", Type: "job", Domain: "workflow", Required: true, Image: "runner", Command: []string{"true"}}}
	release.Spec.Checks[0].Script = checkScript("application")
	release.Spec.Assets = []spec.Asset{{ID: "runner", Type: "image", Source: "example.invalid/runner:1"}}
	release.Spec.Operations = []spec.Operation{{ID: "deploy", Type: "helm"}}
	release.Spec.Transitions = []spec.Transition{{ID: "install", FromRelease: "install", Operations: []string{"deploy"}, Recovery: "repair"}}
	release.Spec.Recovery = []spec.Recovery{{ID: "repair", ToRelease: "1.0.0", Operations: []spec.Operation{{ID: "repair", Type: "helm"}}, Checks: release.Spec.Checks}}
	b, _ := json.Marshal(release)
	write(t, filepath.Join(h.dir, "release.json"), b)
	auth := filepath.Join(h.dir, "source-auth.json")
	write(t, auth, []byte(`{"registries":{}}`))
	r := h.command("release", "lock", filepath.Join(h.dir, "release.json"), "--source-auth", auth, "--out", filepath.Join(h.dir, "lock.json"))
	if r.err == nil || !strings.Contains(r.err.Error(), "outside the release workspace") {
		t.Fatalf("want source credential containment rejection, got %v", r.err)
	}
}

func TestAuthorizationCoversOperationTypes(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	key, pub := filepath.Join(h.dir, "approval.key"), filepath.Join(h.dir, "approval.pub")
	h.ok("trust", "keygen", "--private", key, "--public", pub)
	policyPath := filepath.Join(h.dir, "active-policy.json")
	h.ok("trust", "propose-update", f.policyPath, "--public", pub, "--key-id", "customer", "--role", "approval", "--application", "cli-fixture", "--out", policyPath)
	policy := decode[spec.TrustPolicy](t, read(t, policyPath))
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: "test-only", Context: "test-only", Namespace: "application", ReleaseName: "application", TrustPolicy: policyPath, Profile: "test"}}
	site.Metadata.Name = "test"
	sitePath := filepath.Join(h.dir, "site.json")
	if err := spec.Write(sitePath, site); err != nil {
		t.Fatal(err)
	}
	plan := spec.Plan{Header: spec.NewHeader("Plan"), SitePath: sitePath, Executable: true, PolicyEpoch: policy.Spec.Epoch, Operations: []spec.Operation{{ID: "install-application", Type: "helm"}}, Snapshot: spec.TargetSnapshot{TargetID: "test-target"}}
	plan.Metadata = f.release.Metadata
	plan.PolicyDigest, _ = spec.Digest(policy)
	planPath, authPath := filepath.Join(h.dir, "plan.json"), filepath.Join(h.dir, "authorization.json")
	if err := spec.Write(planPath, plan); err != nil {
		t.Fatal(err)
	}
	h.ok("run", "authorize", planPath, "--key", key, "--key-id", "customer", "--out", authPath)
	a := decode[spec.Authorization](t, read(t, authPath))
	if len(a.Actions) != 1 || a.Actions[0] != "helm" {
		t.Fatalf("authorization must cover operation types: %v", a.Actions)
	}
}

func TestModelHelperRejectsChangedAndAdditionalBytes(t *testing.T) {
	h := newHarness(t)
	dir := filepath.Join(h.dir, "models")
	write(t, filepath.Join(dir, "weights.bin"), []byte("model-v1"))
	manifest := filepath.Join(h.dir, "files.json")
	files := []spec.FileRecord{{Path: "weights.bin", Digest: spec.Hash([]byte("model-v1")), Size: 8}}
	if err := spec.Write(manifest, files); err != nil {
		t.Fatal(err)
	}
	h.ok("helper", "verify-model", "--root", dir, "--manifest", manifest)
	write(t, filepath.Join(dir, "weights.bin"), []byte("model-v2"))
	if r := h.command("helper", "verify-model", "--root", dir, "--manifest", manifest); r.err == nil {
		t.Fatal("changed model accepted")
	}
	write(t, filepath.Join(dir, "weights.bin"), []byte("model-v1"))
	write(t, filepath.Join(dir, "unlisted.bin"), []byte("extra"))
	if r := h.command("helper", "verify-model", "--root", dir, "--manifest", manifest); r.err == nil {
		t.Fatal("additional model accepted")
	}
	if err := os.Remove(filepath.Join(dir, "unlisted.bin")); err != nil {
		t.Fatal(err)
	}
	h.ok("helper", "verify-model", "--root", dir, "--manifest", manifest)
}
