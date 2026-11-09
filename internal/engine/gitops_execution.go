package engine

import (
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func gitOpsPhase(p spec.Plan) bool {
	return p.Kind == "GitOpsPreparePlan" || p.Kind == "GitOpsChecksPlan" || gitOpsDataPhase(p)
}

// GitOpsPreparePlan prepares only fresh native application revision volumes.
// Source adoption and application checks require a separate authorized phase.
func (e *Engine) GitOpsPreparePlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding, reviewedDigest string) (spec.Plan, error) {
	return e.gitOpsPhasePlan(ctx, "GitOpsPreparePlan", v, bundlePath, sitePath, policy, binding, reviewedDigest)
}

// GitOpsChecksPlan runs exact signed checks after fresh controller observation.
func (e *Engine) GitOpsChecksPlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding) (spec.Plan, error) {
	if binding.Contract == nil {
		return spec.Plan{}, spec.Err(2, "GitOps checks require an explicit accepted-source observation contract")
	}
	return e.gitOpsPhasePlan(ctx, "GitOpsChecksPlan", v, bundlePath, sitePath, policy, binding, binding.Contract.ManifestDigest)
}

func (e *Engine) gitOpsPhasePlan(ctx context.Context, kind string, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding, reviewedDigest string) (spec.Plan, error) {
	var p spec.Plan
	if e == nil || v == nil || e.Store == nil || !spec.ValidDigest(v.Digest) || spec.ValidatePolicy(policy) != nil || spec.ValidateSite(e.Site) != nil || spec.ValidateRelease(v.Index.Lock.Release) != nil {
		return p, spec.Err(2, "GitOps execution needs a verified release, explicit Site/policy and durable local journal")
	}
	r := v.Index.Lock.Release
	declared := r.Spec.Deployment.GitOps
	if kind == "GitOpsChecksPlan" && declared != nil && declared.Data != nil {
		return p, spec.Err(10, "mutable application data requires its separately authorized data phase")
	}
	if r.Spec.Deployment.Type != "gitops" || declared == nil || declared.Owner != "argocd" || !spec.ValidGitOpsCommit(declared.Revision) || !gitOpsTargetPath(declared.Path) || e.Site.Spec.Profile != r.Spec.Profile {
		return p, spec.Err(10, "GitOps execution requires the bounded signed Argo directory profile")
	}
	if !filepath.IsAbs(binding.ManifestPath) || !spec.ValidDigest(reviewedDigest) {
		return p, spec.Err(2, "GitOps execution requires an exact reviewed manifest digest and absolute input path")
	}
	manifest, err := ReadGitOpsManifest(binding.ManifestPath)
	if err != nil || spec.Hash(manifest) != reviewedDigest {
		return p, spec.Err(2, "GitOps reviewed manifest is unavailable or differs from its approved digest")
	}
	if contract := r.Spec.Deployment.Configuration; contract != nil {
		if err := checkSiteConfiguration(contract, e.Site.Spec.Values); err != nil {
			return p, err
		}
	}
	appSeeds, fixtureSeeds, err := gitOpsSignedSeeds(v)
	if err != nil {
		return p, err
	}
	if kind == "GitOpsPreparePlan" {
		if binding.Contract != nil || binding.Preparation != nil || !filepath.IsAbs(binding.Repository) || len(appSeeds) == 0 {
			return p, spec.Err(10, "GitOps preparation needs native application seeds, a base repository and no accepted-source/preparation assertion")
		}
	} else {
		if binding.Contract == nil || binding.Repository != "" || spec.ValidateGitOpsProfileContract(*binding.Contract, time.Now()) != nil || binding.Contract.ManifestDigest != reviewedDigest || (len(appSeeds) > 0) != (binding.Preparation != nil) {
			return p, spec.Err(10, "GitOps checks need exact accepted source and explicit application-volume preparation provenance")
		}
	}
	binding.Staging, err = e.gitOpsStageReference(ctx, binding.Staging, v, sitePath, policy, false)
	if err != nil {
		return p, err
	}
	if binding.Preparation != nil {
		reference, err := e.gitOpsPreparationReference(ctx, *binding.Preparation, v, sitePath, policy)
		if err != nil {
			return p, err
		}
		binding.Preparation = &reference
	}
	p = spec.Plan{Header: spec.NewHeader(kind), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, GitOps: &binding, DesiredStateDigest: reviewedDigest, TargetVersion: r.Metadata.Version, Recovery: r.Spec.Recovery, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch, Findings: []spec.Finding{}, Checks: []spec.Check{}, RequiredChecks: []string{}}
	p.Metadata = r.Metadata
	if kind == "GitOpsPreparePlan" {
		p.TransitionID = "gitops-native-preparation"
		p.Operations = appSeeds
	} else {
		p.TransitionID = "gitops-application-checks"
		p.Operations = fixtureSeeds
		p.Checks = r.Spec.Checks
		p.RequiredChecks = r.Spec.RequiredChecks
	}
	if err = e.verifyGitOpsBinding(p, v); err != nil {
		return p, err
	}
	p.SourceSiteDigest, err = sourceSiteDigest(sitePath)
	if err != nil {
		return p, err
	}
	p.SiteDigest, err = spec.Digest(e.Site)
	if err != nil {
		return p, err
	}
	p.PolicyDigest, err = spec.Digest(policy)
	if err != nil {
		return p, err
	}
	p.Snapshot, err = e.inspectGitOpsPlan(ctx, p, v, policy)
	if err != nil {
		return p, err
	}
	p.SnapshotDigest, err = snapshotDigest(p.Snapshot)
	if err != nil {
		return p, err
	}
	e.addPolicyFloorFindings(ctx, &p)
	if kind == "GitOpsChecksPlan" {
		e.addReleaseFloorFindings(ctx, &p)
	}
	e.addExecutionFindings(ctx, &p, v, policy)
	e.addStorageFindings(ctx, &p, v, policy)
	objects, err := PermissionObjects(manifest)
	if err != nil {
		return p, err
	}
	e.addPermissionFindings(ctx, &p, objects)
	p.Findings = append(p.Findings, spec.Finding{Code: "GITOPS_PHASE_SCOPE", Severity: "info", Message: "controller remains the application resource owner; source reachability, warm-cache/fresh-node pulls and data recovery are not established by controller status or registry metadata"})
	return p, nil
}

// gitOpsSignedSeeds separates dedicated check fixtures from application material.
// Unsupported application effects never become implicit preparation or checks.
func gitOpsSignedSeeds(v *bundle.Verified) (application, fixtures []spec.Operation, err error) {
	r := v.Index.Lock.Release
	application, fixtures = []spec.Operation{}, []spec.Operation{}
	fixtureAssets := map[string]bool{}
	for _, check := range r.Spec.Checks {
		for _, asset := range check.Fixtures {
			fixtureAssets[asset] = true
		}
	}
	equal := func(a, b any) bool {
		aa, e1 := spec.Digest(a)
		bb, e2 := spec.Digest(b)
		return e1 == nil && e2 == nil && aa == bb
	}
	for _, op := range r.Spec.Operations {
		switch op.Type {
		case "import", "gitops":
			expected := spec.Operation{ID: op.ID, Type: op.Type, DependsOn: op.DependsOn, Idempotent: op.Idempotent}
			if op.Type == "import" {
				expected.Asset = op.Asset
				if _, err = importTargets(v, op.Asset); err != nil {
					return nil, nil, err
				}
			}
			if !equal(op, expected) {
				return nil, nil, spec.Err(10, "GitOps import/source markers cannot hide application commands or additional effects")
			}
		case "seed":
			if len(op.Command) != 0 || len(op.Args) != 0 || len(op.SecretRefs) != 0 || op.Image != "" || op.Script != nil || op.PVC == "" || op.StorageBytes <= 0 || !nativeMountSupported(op.MountPath) {
				return nil, nil, spec.Err(10, "GitOps preparation supports only exact native fresh-volume seed recipes")
			}
			if fixtureAssets[op.Asset] {
				fixtures = append(fixtures, op)
			} else {
				application = append(application, op)
			}
		case "job", "backup", "migrate", "reindex":
			if r.Spec.Deployment.GitOps == nil || r.Spec.Deployment.GitOps.Data == nil {
				return nil, nil, spec.Err(10, "authored GitOps data effects need an explicit signed data contract")
			}
		default:
			return nil, nil, spec.Err(10, "GitOps application/data procedure is not implemented by this native preparation/check profile")
		}
	}
	application, err = gitOpsOperationOrder(application)
	if err != nil {
		return nil, nil, err
	}
	fixtures, err = gitOpsOperationOrder(fixtures)
	return application, fixtures, err
}

func gitOpsOperationOrder(seeds []spec.Operation) ([]spec.Operation, error) {
	selected := map[string]spec.Operation{}
	for _, seed := range seeds {
		selected[seed.ID] = seed
	}
	states := map[string]int{}
	ordered := make([]spec.Operation, 0, len(seeds))
	var visit func(string) error
	visit = func(id string) error {
		if states[id] == 1 {
			return spec.Err(12, "selected GitOps seed dependencies contain a cycle")
		}
		if states[id] == 2 {
			return nil
		}
		states[id] = 1
		for _, dependency := range selected[id].DependsOn {
			if _, included := selected[dependency]; included {
				if err := visit(dependency); err != nil {
					return err
				}
			}
		}
		states[id] = 2
		ordered = append(ordered, selected[id])
		return nil
	}
	for _, seed := range seeds {
		if err := visit(seed.ID); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func (e *Engine) verifyGitOpsBinding(p spec.Plan, v *bundle.Verified) error {
	if gitOpsDataPhase(p) {
		return e.verifyGitOpsDataBinding(p, v)
	}
	r := v.Index.Lock.Release
	b := p.GitOps
	if p.Kind == "GitOpsChecksPlan" && r.Spec.Deployment.GitOps != nil && r.Spec.Deployment.GitOps.Data != nil {
		return spec.Err(12, "mutable data cannot bypass its separate authorized phase")
	}
	if !gitOpsPhase(p) || b == nil || b.Data != nil || !filepath.IsAbs(b.ManifestPath) || !spec.ValidDigest(p.DesiredStateDigest) || !validGitOpsRunReference(b.Staging) || p.TargetVersion != r.Metadata.Version || p.Metadata.Version != r.Metadata.Version || p.SourceVersion != "" || p.Destructive || p.SourceRun != "" || p.ConfigurationReview != nil || len(p.RetainedResources) != 0 || r.Spec.Deployment.Type != "gitops" || r.Spec.Deployment.GitOps == nil || r.Spec.Deployment.GitOps.Owner != "argocd" {
		return spec.Err(12, "GitOps phase differs from its fixed signed source and execution scope")
	}
	app, fixtures, err := gitOpsSignedSeeds(v)
	if err != nil {
		return err
	}
	expectedOps := fixtures
	expectedChecks := r.Spec.Checks
	expectedRequired := r.Spec.RequiredChecks
	transition := "gitops-application-checks"
	if p.Kind == "GitOpsPreparePlan" {
		expectedOps, expectedChecks, expectedRequired, transition = app, []spec.Check{}, []string{}, "gitops-native-preparation"
		if b.Contract != nil || b.Preparation != nil || b.Repository == "" || len(app) == 0 {
			return spec.Err(12, "GitOps preparation cannot carry accepted-source or prior-volume assertions")
		}
	} else if b.Contract == nil || b.Repository != "" || spec.ValidateGitOpsProfileContract(*b.Contract, time.Now()) != nil || b.Contract.ManifestDigest != p.DesiredStateDigest || (len(app) > 0) != (b.Preparation != nil) || b.Preparation != nil && !validGitOpsRunReference(*b.Preparation) {
		return spec.Err(12, "GitOps checks lack exact accepted-source and application preparation bindings")
	}
	equal := func(a, b any) bool {
		aa, e1 := spec.Digest(a)
		bb, e2 := spec.Digest(b)
		return e1 == nil && e2 == nil && aa == bb
	}
	if p.TransitionID != transition || !equal(p.Operations, expectedOps) || !equal(p.Checks, expectedChecks) || !equal(p.RequiredChecks, expectedRequired) {
		return spec.Err(12, "GitOps phase operations/checks differ from their exact signed selection")
	}
	if e.Site.Spec.StorageProfile == "" && (len(expectedOps) > 0 || r.Spec.MinFreeBytes > 0) && (e.Site.Spec.CapacityBytes <= 0 || e.Site.Spec.CapacityBytes < r.Spec.MinFreeBytes) {
		return spec.Err(10, "native GitOps workers need the declared legacy capacity or a qualified storage profile")
	}
	available := map[string]bool{}
	for _, op := range p.Operations {
		available[op.ID] = true
	}
	for _, op := range r.Spec.Operations {
		if op.Type == "import" || p.Kind == "GitOpsChecksPlan" && (op.Type == "gitops" || slices.ContainsFunc(app, func(seed spec.Operation) bool { return seed.ID == op.ID })) {
			available[op.ID] = true
		}
	}
	for _, op := range p.Operations {
		for _, dep := range op.DependsOn {
			if !available[dep] {
				return spec.Err(10, "GitOps seed dependency is outside the separately verified phase receipts")
			}
		}
	}
	return nil
}

// ValidatePlan rechecks an exact saved plan before an approval is signed.
func (e *Engine) ValidatePlan(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) error {
	return e.checkPlan(ctx, p, v, policy, true)
}
