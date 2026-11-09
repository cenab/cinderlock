package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func TestPlanRejectsUndeclaredScriptImage(t *testing.T) {
	e, client, policy := fixture(t)
	e.Site.Spec.Registry = "registry.internal/app"
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "migrate")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "migrate")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	p, verified := fixturePlan(t, e, policy)
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "runner", Type: "image", Digest: "sha256:" + strings.Repeat("a", 64)}}
	verified.Index.Lock.Release.Spec.Operations[0].Image = "missing-runner"
	client.ClearActions()
	_, err := e.Plan(context.Background(), verified, p.BundlePath, p.SitePath, policy)
	if spec.ExitCode(err) != 2 || !strings.Contains(err.Error(), "nonoptional image asset") {
		t.Fatalf("undeclared script image passed release validation: %v", err)
	}
	if len(client.Actions()) != 0 {
		t.Fatal("invalid script contract reached target inspection")
	}
}

func TestUnknownImportAssetCannotReportSuccess(t *testing.T) {
	e, _, policy := fixture(t)
	p, verified := fixturePlan(t, e, policy)
	e.Site.Spec.Registry = "registry.internal/app"
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "runner", Type: "image", Digest: "sha256:" + strings.Repeat("a", 64)}}
	_, err := e.operation(context.Background(), p, "run", spec.Operation{ID: "import", Type: "import", Asset: "not-in-bundle"}, verified, policy, nil)
	if spec.ExitCode(err) != 10 {
		t.Fatalf("empty import target selection falsely succeeded: %v", err)
	}
}

func TestExecutionProfileRejectsKnownUnsupportedRecipes(t *testing.T) {
	for _, scenario := range []struct{ name, code string }{
		{"operation-image", "OPERATION_IMAGE_MISSING"}, {"operation-exit", "OPERATION_EXIT_UNSUPPORTED"}, {"operation-node-name", "OPERATION_NODE_GPU_UNSUPPORTED"}, {"operation-node-uid", "OPERATION_NODE_GPU_UNSUPPORTED"}, {"operation-gpu", "OPERATION_NODE_GPU_UNSUPPORTED"}, {"operation-negative-gpu", "OPERATION_NODE_GPU_UNSUPPORTED"}, {"import-unknown", "IMPORT_ASSET_MISSING"}, {"import-wrong-type", "IMPORT_ASSET_MISSING"}, {"import-empty", "IMPORT_ASSET_MISSING"}, {"seed-carrier", "OPERATION_IMAGE_MISSING"}, {"seed-capacity", "SEED_PROFILE_UNSUPPORTED"}, {"seed-mount", "JOB_VOLUME_UNSUPPORTED"}, {"seed-command", "OPERATION_COMMAND_MISSING"}, {"operation-file-secret", "JOB_SECRET_FILE_UNSUPPORTED"}, {"check-file-secret", "JOB_SECRET_FILE_UNSUPPORTED"}, {"check-exit", "CHECK_EXIT_UNSUPPORTED"}, {"http-method", "HTTP_METHOD_UNSUPPORTED"}, {"http-host", "HTTP_HOST_NOT_ALLOWED"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			e, _, policy := fixture(t)
			p, verified := fixturePlan(t, e, policy)
			o := &p.Operations[0]
			if strings.HasPrefix(scenario.name, "seed-") {
				o.Type = "seed"
				o.Image = "runner"
				o.Command = []string{"/copy-model"}
				o.PVC = "model-v2"
				o.MountPath = "/models"
				o.StorageBytes = 1024
				o.Asset = "model"
				e.Site.Spec.HelperImage = "runner"
				verified.Index.Lock.Assets = append(verified.Index.Lock.Assets, spec.LockedAsset{ID: "model", Type: "model-tree", Digest: spec.Hash([]byte("tree")), Files: []spec.FileRecord{{Path: "weights.bin", Digest: spec.Hash([]byte("x")), Size: 1}}})
			}
			switch scenario.name {
			case "operation-image":
				o.Image = "absent"
			case "operation-exit":
				o.ExpectedExitCode = 3
			case "operation-node-name":
				o.NodeName = "node"
			case "operation-node-uid":
				o.NodeUID = "node-uid"
			case "operation-gpu":
				o.GPUCount = 1
			case "operation-negative-gpu":
				o.GPUCount = -1
			case "import-unknown":
				*o = spec.Operation{ID: o.ID, Type: "import", Asset: "missing"}
			case "import-wrong-type":
				*o = spec.Operation{ID: o.ID, Type: "import", Asset: "payload"}
				verified.Index.Lock.Assets = append(verified.Index.Lock.Assets, spec.LockedAsset{ID: "payload", Type: "file", Digest: spec.Hash([]byte("file"))})
			case "import-empty":
				*o = spec.Operation{ID: o.ID, Type: "import"}
				verified.Index.Lock.Assets = nil
			case "seed-carrier":
				o.Image = "missing-carrier"
			case "seed-capacity":
				o.StorageBytes = 0
			case "seed-mount":
				o.MountPath = "relative/path"
			case "seed-command":
				o.Command = []string{""}
			case "operation-file-secret":
				e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"input": {File: "local-only"}}
				o.SecretRefs = []string{"input"}
			case "check-file-secret":
				e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"input": {File: "local-only"}}
				p.Checks[0].SecretRefs = []string{"input"}
			case "check-exit":
				p.Checks[0].ExpectedExitCode = 2
			case "http-method", "http-host":
				c := &p.Checks[0]
				c.Type = "http"
				c.Script = nil
				c.Command = nil
				c.URL = "http://api:8080/health"
				c.ExpectedStatus = 200
				e.Site.Spec.AllowedHosts = []string{"api"}
				if scenario.name == "http-method" {
					c.Method = "POST"
				} else {
					e.Site.Spec.AllowedHosts = []string{"another-service"}
				}
			}
			findings := e.ExecutionFindings(context.Background(), p, verified)
			for _, finding := range findings {
				if finding.Code == scenario.code && finding.Severity == "blocker" {
					return
				}
			}
			t.Fatalf("known unsupported recipe was not blocked: %#v", findings)
		})
	}
}

func TestExecutionProfileAllowsExplicitRegistryCredentialFile(t *testing.T) {
	e, _, policy := fixture(t)
	p, verified := fixturePlan(t, e, policy)
	p.Operations = []spec.Operation{{ID: "import", Type: "import", Asset: "runner"}}
	credential := filepath.Join(t.TempDir(), "docker.json")
	if err := os.WriteFile(credential, []byte(`{"auths":{"registry.internal":{"username":"local-user","password":"local-test-password"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"registry": {File: credential}}
	e.Site.Spec.RegistryAuthRef = "registry"
	snapshot, err := e.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.Snapshot = snapshot
	for _, finding := range e.ExecutionFindings(context.Background(), p, verified) {
		if finding.Severity == "blocker" {
			t.Fatalf("supported registry file reference rejected: %#v", finding)
		}
	}
}

func TestExecutionAdmissionRequiresCheckAndPhaseCapabilities(t *testing.T) {
	for _, test := range []struct {
		kind    string
		actions []string
	}{
		{"Plan", []string{"job"}},
		{"ArtifactsPlan", []string{"gitops-stage"}},
		{"GitOpsPreparePlan", []string{"gitops-prepare"}},
		{"GitOpsChecksPlan", []string{"gitops-check", "gitops-observe"}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			e, _, policy := fixture(t)
			e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, test.actions...)
			policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, test.actions...)
			p, v := fixturePlan(t, e, policy)
			p.Kind = test.kind
			if err := e.checkExecutionProfile(context.Background(), p, v, policy); err != nil {
				t.Fatalf("admitted capabilities rejected: %v", err)
			}
			for _, owner := range []string{"site", "policy"} {
				for _, action := range test.actions {
					t.Run(owner+"/"+action, func(t *testing.T) {
						siteActions := e.Site.Spec.AllowedActions
						defer func() { e.Site.Spec.AllowedActions = siteActions }()
						denied := policy
						if owner == "site" {
							e.Site.Spec.AllowedActions = slices.DeleteFunc(slices.Clone(siteActions), func(s string) bool { return s == action })
						} else {
							denied.Spec.AllowedActions = slices.DeleteFunc(slices.Clone(policy.Spec.AllowedActions), func(s string) bool { return s == action })
						}
						if err := e.checkExecutionProfile(context.Background(), p, v, denied); spec.ExitCode(err) != 16 || !strings.Contains(err.Error(), action) {
							t.Fatalf("missing %s capability %s was admitted: %v", owner, action, err)
						}
					})
				}
			}
		})
	}
}

func TestPolicyFloorRequiresExplicitBaselineAndStopsOldPlans(t *testing.T) {
	e, client, policy := fixture(t)
	p, verified := fixturePlan(t, e, policy)
	unenrolled, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer unenrolled.Close()
	e.Store = unenrolled
	client.ClearActions()
	plan, err := e.Plan(context.Background(), verified, p.BundlePath, p.SitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range plan.Findings {
		if finding.Code == "POLICY_BASELINE_MISSING" {
			found = true
		}
	}
	if !found || plan.Executable {
		t.Fatal("missing target policy baseline was not an actionable blocker")
	}
	if _, err := unenrolled.PolicyFloor(context.Background(), p.Snapshot.TargetID); !errors.Is(err, state.ErrPolicyFloorMissing) {
		t.Fatal("read-only planning silently enrolled trust")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" && !(action.GetVerb() == "create" && action.GetResource().Resource == "selfsubjectaccessreviews") {
			t.Fatalf("planning mutated workload resource: %s", action.GetVerb())
		}
	}
	if err := unenrolled.ObservePolicyFloor(context.Background(), p.Snapshot.TargetID, p.PolicyEpoch, p.PolicyDigest); err != nil {
		t.Fatal(err)
	}
	if err := e.checkPlan(context.Background(), p, verified, policy, false); err != nil {
		t.Fatalf("explicit baseline did not admit exact policy: %v", err)
	}
	next := policy
	next.Spec.Epoch++
	digest, err := spec.Digest(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := unenrolled.ObservePolicyFloor(context.Background(), p.Snapshot.TargetID, next.Spec.Epoch, digest); err != nil {
		t.Fatal(err)
	}
	if err := e.checkPlan(context.Background(), p, verified, policy, false); spec.ExitCode(err) != 16 {
		t.Fatalf("old saved plan continued after floor advanced: %v", err)
	}
}
