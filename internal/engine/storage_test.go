package engine

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/storageplan"
)

func storageFixture(t *testing.T) (*Engine, spec.TrustPolicy, spec.Plan, *bundle.Verified) {
	t.Helper()
	e, _, policy := fixture(t)
	e.Site.Spec.StorageProfile = storageplan.Profile
	e.Site.Spec.StorageOperatorPath = e.StateDir
	e.Site.Spec.CapacityBytes = 0
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "storage-assertions")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "storage-assertions")
	policy.Spec.Epoch++
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, domain := range []string{"registry", "runtime", "models", "indexes", "migrations", "backups"} {
		free, retained := int64(1000000), int64(50)
		e.Site.Spec.StorageCapacities = append(e.Site.Spec.StorageCapacities, spec.StorageCapacity{Domain: domain, Binding: domain + "-pool", Source: "synthetic test assertion, not a target measurement", AvailableBytes: &free, RetainedBytes: &retained, ObservedAt: now, Status: "asserted"})
	}
	admitFixturePolicy(t, e, policy)
	p, verified := fixturePlan(t, e, policy)
	for _, domain := range []string{"operator", "registry", "runtime", "models", "indexes", "migrations", "backups"} {
		verified.Index.Lock.Release.Spec.StorageBudgets = append(verified.Index.Lock.Release.Spec.StorageBudgets, spec.StorageBudget{Domain: domain, AdditionalBytes: 100, TemporaryBytes: 20})
	}
	verified.Root = t.TempDir()
	verified.Index.Payloads = []spec.Descriptor{{Path: "blobs/sha256/payload", Digest: spec.Hash([]byte("payload")), Size: 30}}
	p.BundlePath = filepath.Join(e.StateDir, "test.bundle")
	if err := os.WriteFile(p.BundlePath, []byte(strings.Repeat("x", 100)), 0600); err != nil {
		t.Fatal(err)
	}
	return e, policy, p, verified
}

func TestExplicitStoragePlanObservesOperatorAndBindsInitialApplyMetadata(t *testing.T) {
	e, policy, p, verified := storageFixture(t)
	assessment, err := e.StoragePlan(context.Background(), p, verified, policy)
	if err != nil || !assessment.Executable {
		t.Fatalf("supported storage control rejected: %#v %v", assessment, err)
	}
	observed := false
	for _, domain := range assessment.Domains {
		if domain.Domain == "operator" {
			observed = domain.Confidence == "observed_and_declared" && domain.AvailableBytes != nil && strings.HasPrefix(domain.Binding, "operator-fs:")
		}
	}
	if !observed {
		t.Fatal("operator free space was not represented as a local observation")
	}
	p.Storage = &assessment
	if err := e.checkStoragePlan(context.Background(), p, verified, policy, true); err != nil {
		t.Fatalf("fresh local free-space movement made a valid saved plan stale: %v", err)
	}
	corrupted := assessment
	corrupted.Domains = slices.Clone(assessment.Domains)
	corrupted.Domains[0].PeakBytes++
	p.Storage = &corrupted
	if err := e.checkStoragePlan(context.Background(), p, verified, policy, true); spec.ExitCode(err) != 11 {
		t.Fatalf("edited storage assessment accepted: %v", err)
	}
	p.Storage = &assessment
	for i := range e.Site.Spec.StorageCapacities {
		if e.Site.Spec.StorageCapacities[i].Domain == "runtime" {
			value := int64(0)
			e.Site.Spec.StorageCapacities[i].AvailableBytes = &value
		}
	}
	if err := e.checkStoragePlan(context.Background(), p, verified, policy, true); spec.ExitCode(err) != 10 {
		t.Fatalf("initial execution ignored insufficient refreshed capacity: %v", err)
	}
}

func TestPlanAttachesScopedStorageAndDoesNotUseLegacyScalarForExplicitProfile(t *testing.T) {
	e, policy, p, verified := storageFixture(t)
	plan, err := e.Plan(context.Background(), verified, p.BundlePath, p.SitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Storage == nil || !plan.Storage.Executable || plan.Storage.RequirementsDigest == "" {
		t.Fatalf("normal planner did not attach a scoped storage assessment: %#v", plan.Storage)
	}
	for _, finding := range plan.Findings {
		if finding.Code == "CAPACITY_UNVERIFIED" || finding.Code == "STORAGE_LEGACY_UNQUALIFIED" {
			t.Fatalf("explicit storage profile fell back to legacy capacity: %#v", finding)
		}
	}
}

func TestStorageAccountingCountsPerRepositoryAndSelectedModelCopies(t *testing.T) {
	_, _, p, verified := storageFixture(t)
	file := spec.FileRecord{Path: "layer", Digest: spec.Hash([]byte("same-layer")), Size: 10}
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "image-one", Type: "image", Files: []spec.FileRecord{file}}, {ID: "image-two", Type: "image", Files: []spec.FileRecord{file}}, {ID: "model", Type: "model-tree", Files: []spec.FileRecord{{Path: "one.bin", Digest: spec.Hash([]byte("one")), Size: 3}, {Path: "two.bin", Digest: spec.Hash([]byte("two")), Size: 7}}}}
	p.Operations = []spec.Operation{{ID: "import", Type: "import"}, {ID: "model-one", Type: "seed", Asset: "model", PVC: "model-one"}, {ID: "model-two", Type: "seed", Asset: "model", PVC: "model-two"}}
	inventory, _, _, err := storageInventory(p, verified)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.ImageCompressedBytes != 20 || inventory.ModelBytes != 20 || inventory.LargestModelFileBytes != 7 {
		t.Fatalf("storage accounting assumed unsupported cross-repository/PVC deduplication: %#v", inventory)
	}
}

func TestStorageUnknownProfileAndUnavailableLocalProbeCannotPass(t *testing.T) {
	e, policy, p, verified := storageFixture(t)
	e.Site.Spec.StorageProfile = "unqualified-profile"
	assessment, err := e.StoragePlan(context.Background(), p, verified, policy)
	if err != nil || assessment.Executable {
		t.Fatalf("unknown storage profile passed: %#v %v", assessment, err)
	}
	e.Site.Spec.StorageProfile = storageplan.Profile
	e.Site.Spec.StorageOperatorPath = filepath.Join(t.TempDir(), "does-not-exist")
	assessment, err = e.StoragePlan(context.Background(), p, verified, policy)
	if err != nil || assessment.Executable {
		t.Fatalf("unobserved operator storage passed: %#v %v", assessment, err)
	}
}
