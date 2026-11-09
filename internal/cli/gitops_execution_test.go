package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func TestGitOpsChecksCLIRequiresActualStagingAndSeparateCurrentApproval(t *testing.T) {
	f, sitePath, _ := gitOpsCLIFixture(t)
	f.release.Spec.Deployment.GitOps.Owner = "argocd"
	f.releasePath, f.lockPath, f.bundlePath = filepath.Join(f.h.dir, "checks-release.json"), filepath.Join(f.h.dir, "checks.lock.json"), filepath.Join(f.h.dir, "checks.cinder")
	if err := spec.Write(f.releasePath, f.release); err != nil {
		t.Fatal(err)
	}
	f.h.ok("release", "lock", f.releasePath, "--out", f.lockPath)
	f.h.ok("bundle", "build", f.lockPath, "--key", f.keyPath, "--key-id", "release", "--out", f.bundlePath)
	manifest := filepath.Join(f.h.dir, "reviewed.yaml")
	f.h.ok("gitops", "export", f.bundlePath, "--site", sitePath, "--out", manifest)
	repository, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contract := spec.GitOpsProfileContract{Header: spec.NewHeader("GitOpsProfileContract"), Profile: "argocd-directory-v1", Namespace: "argocd", Name: "application", UID: "application-uid", Repository: repository, RepositoryURL: "https://git.internal/app.git", AcceptedRevision: strings.Repeat("b", 40), ManifestDigest: spec.Hash(read(t, manifest)), NotBefore: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), MaxAgeSeconds: 3600}
	contractPath := filepath.Join(f.h.dir, "contract.json")
	if err := spec.Write(contractPath, contract); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.h.dir, "checks-plan.json")
	args := []string{"gitops", "checks-plan", f.bundlePath, "--site", sitePath, "--contract", contractPath, "--manifest", manifest, "--staging-run", "unrecorded-stage", "--out", out}
	result := f.h.command(args...)
	if spec.ExitCode(result.err) != 10 || !strings.Contains(result.err.Error(), "required GitOps phase") {
		t.Fatal("checks CLI accepted a claimed stage without its exact original run", result.err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("blocked constructor wrote an executable proposal", err)
	}
	// Phase approval must revalidate the actual plan; a ready flag is never authority.
	p := spec.Plan{Header: spec.NewHeader("GitOpsChecksPlan"), Executable: true, BundlePath: f.bundlePath, SitePath: sitePath, GitOps: &spec.GitOpsPlanBinding{ManifestPath: manifest, Contract: &contract}, PolicyEpoch: 1}
	planPath := filepath.Join(f.h.dir, "unbound-checks-plan.json")
	if err := spec.Write(planPath, p); err != nil {
		t.Fatal(err)
	}
	authorization := filepath.Join(f.h.dir, "authorization.json")
	result = f.h.command("run", "authorize", planPath, "--key", f.keyPath, "--key-id", "release", "--out", authorization)
	if result.err == nil {
		t.Fatal("unbound phase received an execution authorization")
	}
	if _, err := os.Stat(authorization); !os.IsNotExist(err) {
		t.Fatal("failed current validation wrote an authorization", err)
	}
	// The known terminal preparation state is successful materialization only.
	store, err := state.Open(filepath.Join(f.h.state, "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body, _ := spec.Canonical(p)
	digest, _ := spec.Digest(p)
	if err := store.CreateRun(context.Background(), state.Run{ID: "prepared-status", Application: "cli-fixture", Namespace: "test", TargetID: "target", PlanDigest: digest, BundleDigest: spec.Hash([]byte("bundle")), Plan: body, Site: read(t, sitePath)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetState(context.Background(), "prepared-status", "gitops_prepared", false, spec.RunResult{State: "gitops_prepared", Acceptance: "not_established"}); err != nil {
		t.Fatal(err)
	}
	status := f.h.command("run", "status", "prepared-status", "--check")
	if spec.ExitCode(status.err) != 10 || decode[state.Run](t, status.result).Active {
		t.Fatal("prepared-only status became application success or retained an active gate", status.err)
	}
}

func TestGitOpsPrepareCLIRejectsOutputInsideSource(t *testing.T) {
	f, site, _ := gitOpsCLIFixture(t)
	repository, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(repository, "plan.json")
	result := f.h.command("gitops", "prepare-plan", f.bundlePath, "--site", site, "--repository", repository, "--manifest", filepath.Join(f.h.dir, "desired.yaml"), "--approved-manifest-digest", spec.Hash([]byte("reviewed")), "--staging-run", "stage", "--out", out)
	if result.err == nil || !strings.Contains(result.err.Error(), "outside the source repository") {
		t.Fatal("prepare CLI did not enforce inert source boundaries", result.err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("phase planning wrote inside the source repository", err)
	}
}
