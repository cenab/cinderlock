package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestGitOpsDataApprovalRevalidatesRatherThanSigningAReadyFlag(t *testing.T) {
	f, sitePath, manifest := gitOpsCLIFixture(t)
	policy := decode[spec.TrustPolicy](t, read(t, f.policyPath))
	policy.Spec.Epoch++
	policy.Spec.Keys[0].Roles = append(policy.Spec.Keys[0].Roles, "approval")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "gitops-data")
	policyBody, err := spec.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	write(t, f.policyPath, policyBody)
	site := decode[spec.Site](t, read(t, sitePath))
	site.Spec.AllowedActions = append(site.Spec.AllowedActions, "gitops-data")
	siteBody, err := spec.Canonical(site)
	if err != nil {
		t.Fatal(err)
	}
	write(t, sitePath, siteBody)
	digest, err := spec.Digest(policy)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contract := &spec.GitOpsProfileContract{Header: spec.NewHeader("GitOpsProfileContract"), Profile: "argocd-directory-v1", Namespace: "argocd", Name: "app", UID: "application-uid", Repository: repository, RepositoryURL: "https://git.internal/app.git", AcceptedRevision: strings.Repeat("a", 40), ManifestDigest: spec.Hash(read(t, manifest)), NotBefore: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), MaxAgeSeconds: 3600}
	for _, kind := range []string{"GitOpsDataPlan", "GitOpsDataChecksPlan", "GitOpsDataRecoveryPlan"} {
		p := spec.Plan{Header: spec.NewHeader(kind), Executable: true, SitePath: sitePath, BundlePath: f.bundlePath, PolicyDigest: digest, PolicyEpoch: policy.Spec.Epoch, GitOps: &spec.GitOpsPlanBinding{ManifestPath: manifest, Contract: contract, Data: &spec.GitOpsDataBinding{PVC: "data", UID: "data-uid", Revision: "schema-1"}}}
		p.Metadata = f.release.Metadata
		p.Recovery = f.release.Spec.Recovery
		p.Snapshot.TargetID = spec.Hash([]byte("claimed-target"))
		plan := filepath.Join(f.h.dir, kind+".json")
		if err := spec.Write(plan, p); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(f.h.dir, kind+"-authorization.json")
		result := f.h.command("run", "authorize", plan, "--key", f.keyPath, "--key-id", "release", "--out", output)
		if result.err == nil || !strings.Contains(result.err.Error(), "GitOps data plan differs") {
			t.Fatal("forged executable data phase escaped current exact-plan validation", kind, result.err)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("blocked data phase wrote an approval", err)
		}
	}
}

func TestGitOpsInitialDataCLIRequiresOriginalClaimAndStaging(t *testing.T) {
	h := newHarness(t)
	result := h.command("gitops", "data-checks-plan", "unused.cinder", "--site", "unused-site.json", "--manifest", "unused.yaml", "--contract", "unused-contract.json", "--initial-data", "--out", filepath.Join(h.dir, "plan.json"))
	if spec.ExitCode(result.err) != 2 || !strings.Contains(result.err.Error(), "independently selected --data-uid") {
		t.Fatal("initial data CLI silently selected a claim or staging history", result.err)
	}
}
