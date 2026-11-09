package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type gitOpsDataFixture struct {
	*gitOpsExecutionFixture
	baseline       spec.RunResult
	oldManifest    string
	futureManifest string
	targetObjects  []map[string]any
	targetBase     string
	staging        spec.GitOpsRunReference
	before         *spec.RunResult
	prePlan        spec.Plan
}

func newGitOpsDataUpgradeFixture(t *testing.T, models bool) *gitOpsDataFixture {
	t.Helper()
	ctx := context.Background()
	f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{models: models, data: true})
	initial, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil || !initial.Executable {
		t.Fatal("initial data control", err, initial.Findings)
	}
	accepted, err := f.e.Apply(ctx, initial, f.v, f.policy, f.approval(t, initial), false)
	if err != nil {
		t.Fatal("initial application control", err)
	}
	fixture := &gitOpsDataFixture{gitOpsExecutionFixture: f, baseline: accepted, oldManifest: f.binding.ManifestPath, targetBase: f.contract.AcceptedRevision}
	f.e.Site.Spec.BackupRef = "synthetic-backup-v2"
	if err := os.WriteFile(f.sitePath, mustCanonical(t, f.e.Site), 0600); err != nil {
		t.Fatal(err)
	}
	r := &f.v.Index.Lock.Release
	r.Metadata.Sequence++
	f.v.Digest = spec.Hash([]byte("signed-data-upgrade-target"))
	r.Spec.Deployment.GitOps.Revision = fixture.targetBase
	r.Spec.Deployment.GitOps.Data = &spec.GitOpsDataProcedures{PVC: "application-data", Quiesce: "quiesce", Backup: "backup", Resume: "writes"}
	procedure := func(id, kind, dependency string) spec.Operation {
		op := spec.Operation{ID: id, Type: kind, Image: "runner", Command: []string{"/app/" + id}, PVC: "application-data", MountPath: "/data", TimeoutSeconds: 5, Idempotent: true, Script: fixtureScript("workflow")}
		if dependency != "" {
			op.DependsOn = []string{dependency}
		}
		return op
	}
	var nextFixtures []spec.Operation
	fixtureAssets := map[string]bool{}
	for _, check := range r.Spec.Checks {
		for _, asset := range check.Fixtures {
			fixtureAssets[asset] = true
		}
	}
	for _, op := range r.Spec.Operations {
		if op.Type == "seed" && fixtureAssets[op.Asset] {
			op.PVC += "-next"
			op.DependsOn = []string{"sync"}
			nextFixtures = append(nextFixtures, op)
		}
	}
	r.Spec.Operations = []spec.Operation{procedure("quiesce", "job", ""), procedure("backup", "backup", "quiesce"), procedure("schema", "migrate", "backup"), {ID: "sync", Type: "gitops", DependsOn: []string{"schema"}}, procedure("writes", "job", "sync")}
	r.Spec.Transitions = []spec.Transition{{ID: "data-upgrade", FromRelease: r.Metadata.Version, FromDataRevision: "schema-1", ToDataRevision: "schema-2", Operations: []string{"quiesce", "backup", "schema", "sync", "writes"}, Recovery: "restore"}}
	r.Spec.Operations = append(r.Spec.Operations, nextFixtures...)
	for _, op := range nextFixtures {
		r.Spec.Transitions[0].Operations = append(r.Spec.Transitions[0].Operations, op.ID)
	}
	r.Spec.Recovery = []spec.Recovery{{ID: "restore", ToRelease: r.Metadata.Version, DataRevision: "schema-2", RequiresBackup: true, GitOpsData: &spec.GitOpsDataProcedures{PVC: "application-data", Quiesce: "restore-quiesce", Resume: "restore-writes"}, Operations: []spec.Operation{procedure("restore-quiesce", "job", ""), procedure("restore-data", "job", "restore-quiesce"), procedure("restore-writes", "job", "restore-data")}, Checks: r.Spec.Checks}}
	if len(nextFixtures) > 0 {
		recoverySeeds := []spec.Operation{}
		for _, seed := range nextFixtures {
			seed.ID = "recovery-" + seed.ID
			seed.PVC += "-recovery"
			seed.DependsOn = nil
			recoverySeeds = append(recoverySeeds, seed)
		}
		r.Spec.Recovery[0].Operations[0].DependsOn = []string{recoverySeeds[len(recoverySeeds)-1].ID}
		r.Spec.Recovery[0].Operations = append(recoverySeeds, r.Spec.Recovery[0].Operations...)
	}
	if models {
		// Exercise observing an old model under a future release that removes it.
		r.Spec.AIProfile = spec.AIProfile{}
	}
	objects, err := PermissionObjects(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if object["kind"] == "ConfigMap" {
			object["data"] = map[string]any{"setting": "future-config"}
		}
		if models && object["kind"] == "Deployment" {
			pod := object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			pod["volumes"] = []any{map[string]any{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": "application-data"}}}
			pod["containers"].([]any)[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "data", "mountPath": "/data"}}
		}
	}
	manifest, err := encodeObjects(objects)
	if err != nil {
		t.Fatal(err)
	}
	oldRenderer := f.e.HelmRunner
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "template" {
			return manifest, nil
		}
		return oldRenderer(ctx, args...)
	}
	fixture.futureManifest = filepath.Join(f.e.StateDir, "data-target.yaml")
	fixture.targetObjects = objects
	if err := os.WriteFile(fixture.futureManifest, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	newStage, err := f.e.ArtifactsPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy)
	if err != nil || !newStage.Executable {
		t.Fatal("upgrade image stage", err, newStage.Findings)
	}
	imported, err := f.e.Apply(ctx, newStage, f.v, f.policy, f.approval(t, newStage), false)
	if err != nil {
		t.Fatal(err)
	}
	fixture.staging = spec.GitOpsRunReference{RunID: imported.RunID}
	return fixture
}

func (f *gitOpsDataFixture) prepare(t *testing.T) spec.RunResult {
	t.Helper()
	ctx := context.Background()
	b := spec.GitOpsPlanBinding{ManifestPath: f.futureManifest, Staging: f.staging, Contract: &f.contract, Data: &spec.GitOpsDataBinding{PVC: "application-data", UID: "application-data-uid", Revision: "schema-1", BackupRef: f.e.Site.Spec.BackupRef, Previous: &spec.GitOpsRunReference{RunID: f.baseline.RunID}, PreviousManifestPath: f.oldManifest}}
	manifest, err := ReadGitOpsManifest(f.futureManifest)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.e.GitOpsDataPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, b, spec.Hash(manifest))
	if err != nil || !p.Executable {
		t.Fatal("pre-adoption plan", err, p.Findings)
	}
	result, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
	if err != nil || result.State != "awaiting_adoption" || result.Acceptance != "not_established" {
		t.Fatal("pre-adoption execution", err, result)
	}
	f.before, f.prePlan = &result, p
	return result
}

func (f *gitOpsDataFixture) adopt(t *testing.T, rotate bool) spec.GitOpsPlanBinding {
	t.Helper()
	if f.before == nil {
		t.Fatal("source adoption must follow the actual data predecessor")
	}
	f.reviewObjects(t, f.targetObjects)
	f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision = f.targetBase
	for i, object := range f.targetObjects {
		if object["kind"] == "ConfigMap" {
			f.live[i].Object["data"] = object["data"]
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, path := range [][]string{{"status", "reconciledAt"}, {"status", "operationState", "startedAt"}, {"status", "operationState", "finishedAt"}} {
		profileSet(t, f.application, now, path...)
	}
	finished, err := time.Parse(time.RFC3339Nano, f.before.FinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	f.contract.NotBefore = finished.Truncate(time.Second).Format(time.RFC3339Nano)
	f.seed(t)
	if rotate {
		f.rotateAuthority(t)
	}
	f.e.Site.Spec.DataRevision = "schema-2"
	if err := os.WriteFile(f.sitePath, mustCanonical(t, f.e.Site), 0600); err != nil {
		t.Fatal(err)
	}
	return spec.GitOpsPlanBinding{ManifestPath: f.futureManifest, Contract: &f.contract, Data: &spec.GitOpsDataBinding{PVC: "application-data", UID: "application-data-uid", Revision: "schema-2", BackupRef: f.e.Site.Spec.BackupRef, Predecessor: &spec.GitOpsRunReference{RunID: f.before.RunID}}}
}

func (f *gitOpsDataFixture) rotateAuthority(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = private
	f.policy.Spec.Epoch++
	f.policy.Spec.Keys[0].PublicKey = base64.StdEncoding.EncodeToString(public)
	if err := os.WriteFile(f.e.Site.Spec.TrustPolicy, mustCanonical(t, f.policy), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.e.Store.ObservePolicyFloor(ctx, f.e.Site.Spec.ClusterID, f.policy.Spec.Epoch, mustDigest(t, f.policy)); err != nil {
		t.Fatal(err)
	}
	secret, err := f.kube.CoreV1().Secrets("test").Get(ctx, "workflow-token", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.Data["token"] = []byte("rotated-private-test-token")
	if _, err := f.kube.CoreV1().Secrets("test").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}
