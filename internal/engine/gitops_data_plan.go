package engine

import (
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func gitOpsDataPhase(p spec.Plan) bool {
	return p.Kind == "GitOpsDataPlan" || p.Kind == "GitOpsDataChecksPlan" || p.Kind == "GitOpsDataRecoveryPlan"
}

func gitOpsApplicationChecks(p spec.Plan) bool {
	return p.Kind == "GitOpsChecksPlan" || p.Kind == "GitOpsDataChecksPlan" || p.Kind == "GitOpsDataRecoveryPlan"
}

func (e *Engine) GitOpsDataPlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding, reviewedDigest string) (spec.Plan, error) {
	return e.gitOpsDataPlan(ctx, "GitOpsDataPlan", v, bundlePath, sitePath, policy, binding, reviewedDigest)
}

func (e *Engine) GitOpsDataChecksPlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding) (spec.Plan, error) {
	if binding.Contract == nil {
		return spec.Plan{}, spec.Err(2, "data checks require an accepted-source contract")
	}
	return e.gitOpsDataPlan(ctx, "GitOpsDataChecksPlan", v, bundlePath, sitePath, policy, binding, binding.Contract.ManifestDigest)
}

func gitOpsDataPreChecks(r spec.Release) []spec.Check {
	checks := []spec.Check{}
	for _, c := range r.Spec.Checks {
		if c.Type == "endpoint" || r.Spec.License != nil && r.Spec.License.Check == c.ID {
			checks = append(checks, c)
		}
	}
	return checks
}

func (e *Engine) gitOpsDataPlan(ctx context.Context, kind string, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding, reviewedDigest string) (spec.Plan, error) {
	var p spec.Plan
	if e == nil || e.Store == nil || v == nil || spec.ValidateRelease(v.Index.Lock.Release) != nil || spec.ValidatePolicy(policy) != nil || spec.ValidateSite(e.Site) != nil || !spec.ValidDigest(v.Digest) || binding.Data == nil || binding.Contract == nil || !filepath.IsAbs(binding.ManifestPath) || !spec.ValidDigest(reviewedDigest) {
		return p, spec.Err(2, "GitOps data plans need verified inputs, explicit reviewed source and mutable-claim bindings")
	}
	r := v.Index.Lock.Release
	if r.Spec.Deployment.Type != "gitops" || r.Spec.Deployment.GitOps == nil || r.Spec.Deployment.GitOps.Data == nil || r.Spec.Deployment.GitOps.Owner != "argocd" || r.Spec.Profile != e.Site.Spec.Profile || needsHardware(r.Spec.AIProfile) {
		return p, spec.Err(10, "GitOps data requires the supported signed CPU Argo directory profile")
	}
	if spec.ValidateGitOpsProfileContract(*binding.Contract, time.Now()) != nil || binding.Repository != "" || binding.Data.Recovery != "" {
		return p, spec.Err(2, "GitOps data phase has an invalid accepted-source contract or procedure scope")
	}
	data := *binding.Data
	binding.Data = &data
	p = spec.Plan{Header: spec.NewHeader(kind), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, GitOps: &binding, DesiredStateDigest: reviewedDigest, TargetVersion: r.Metadata.Version, Recovery: r.Spec.Recovery, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch, Findings: []spec.Finding{}, Checks: []spec.Check{}, RequiredChecks: []string{}}
	p.Metadata = r.Metadata
	if kind == "GitOpsDataPlan" {
		if data.Initial || data.Previous == nil || data.Predecessor != nil || !filepath.IsAbs(data.PreviousManifestPath) {
			return p, spec.Err(2, "pre-adoption data needs the exact previous accepted run and reviewed old manifest")
		}
		ref, previous, _, err := e.acceptedGitOpsReference(ctx, *data.Previous)
		if err != nil {
			return p, err
		}
		data.Previous = &ref
		p.SourceVersion = previous.TargetVersion
		if p.SourceVersion == "" {
			p.SourceVersion = previous.Metadata.Version
		}
		if previous.GitOps.Data == nil || previous.GitOps.Data.PVC != data.PVC || previous.GitOps.Data.UID != data.UID || previous.Metadata.Channel != r.Metadata.Channel || previous.Metadata.Application != r.Metadata.Application || previous.Metadata.Sequence >= r.Metadata.Sequence || r.Spec.Deployment.GitOps.Revision != previous.GitOps.Contract.AcceptedRevision {
			return p, spec.Err(11, "data upgrade does not continue the accepted source, claim, channel and release sequence")
		}
	} else if data.Initial {
		if data.Previous != nil || data.Predecessor != nil || data.PreviousManifestPath != "" {
			return p, spec.Err(2, "initial data adoption cannot substitute an upgrade predecessor")
		}
	} else {
		if data.Predecessor == nil {
			return p, spec.Err(2, "post-adoption data needs its exact active awaiting-adoption predecessor")
		}
		ref, previous, _, _, err := e.gitOpsDataRun(ctx, *data.Predecessor, v)
		if err != nil {
			return p, err
		}
		if previous.Kind != "GitOpsDataPlan" {
			return p, spec.Err(10, "post-adoption data can continue only its pre-adoption procedure")
		}
		data.Predecessor = &ref
		data.Previous = previous.GitOps.Data.Previous
		data.PreviousManifestPath = previous.GitOps.Data.PreviousManifestPath
		binding.Staging = previous.GitOps.Staging
		binding.Preparation = previous.GitOps.Preparation
		p.SourceRun = ref.RunID
		p.SourceVersion = previous.SourceVersion
	}
	from := p.SourceVersion
	if data.Initial {
		from = "install"
	}
	cut, err := gitOpsDataSelection(r, from)
	if err != nil {
		return p, err
	}
	p.TransitionID = cut.transition.ID
	if kind == "GitOpsDataPlan" {
		p.Operations = cut.before
		p.Checks = gitOpsDataPreChecks(r)
	} else {
		p.Operations = cut.after
		p.Checks = r.Spec.Checks
		p.RequiredChecks = r.Spec.RequiredChecks
	}
	for _, op := range p.Operations {
		p.Destructive = p.Destructive || op.Destructive
	}
	binding.Staging, err = e.gitOpsHistoricalStage(ctx, binding.Staging, v, false)
	if err != nil {
		return p, err
	}
	models, _, err := gitOpsSignedSeeds(v)
	if err != nil {
		return p, err
	}
	if (len(models) > 0) != (binding.Preparation != nil) {
		return p, spec.Err(10, "data release needs its exact completed native model preparation")
	}
	if binding.Preparation != nil {
		ref, prepared, _, err := e.gitOpsHistoricalPreparation(ctx, *binding.Preparation, v)
		if err != nil {
			return p, err
		}
		if prepared.DesiredStateDigest != reviewedDigest {
			return p, spec.Err(11, "model preparation belongs to a different reviewed target manifest")
		}
		binding.Preparation = &ref
	}
	if err := e.verifyGitOpsDataBinding(p, v); err != nil {
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
	p.Snapshot, err = e.inspectGitOpsData(ctx, p, v, policy)
	if err != nil {
		return p, err
	}
	p.SnapshotDigest, err = snapshotDigest(p.Snapshot)
	if err != nil {
		return p, err
	}
	e.addPolicyFloorFindings(ctx, &p)
	e.addReleaseFloorFindings(ctx, &p)
	e.addExecutionFindings(ctx, &p, v, policy)
	e.addStorageFindings(ctx, &p, v, policy)
	manifestPath := binding.ManifestPath
	if kind == "GitOpsDataPlan" {
		manifestPath = data.PreviousManifestPath
	}
	manifest, err := ReadGitOpsManifest(manifestPath)
	if err != nil {
		return p, err
	}
	objects, err := PermissionObjects(manifest)
	if err != nil {
		return p, err
	}
	e.addPermissionFindings(ctx, &p, objects)
	p.Findings = append(p.Findings, spec.Finding{Code: "GITOPS_DATA_SCOPE", Severity: "info", Message: "signed application procedures and bounded current claim/worker identities; no storage fencing, future writer exclusion, generic backup verification or production restore qualification"})
	return p, nil
}

func sameGitOpsValue(a, b any) bool {
	aa, aErr := spec.Digest(struct {
		Value any `json:"value"`
	}{a})
	bb, bErr := spec.Digest(struct {
		Value any `json:"value"`
	}{b})
	return aErr == nil && bErr == nil && aa == bb
}

func (e *Engine) verifyGitOpsDataBinding(p spec.Plan, v *bundle.Verified) error {
	r := v.Index.Lock.Release
	b := p.GitOps
	if !gitOpsDataPhase(p) || b == nil || b.Data == nil || b.Contract == nil || b.Repository != "" || !filepath.IsAbs(b.ManifestPath) || !spec.ValidDigest(p.DesiredStateDigest) || !validGitOpsRunReference(b.Staging) || r.Spec.Deployment.Type != "gitops" || r.Spec.Deployment.GitOps == nil || r.Spec.Deployment.GitOps.Data == nil || r.Spec.Deployment.GitOps.Owner != "argocd" || p.Metadata.Version != r.Metadata.Version || p.ConfigurationReview != nil || len(p.RetainedResources) != 0 {
		return spec.Err(12, "GitOps data plan differs from its exact signed deployment and claim scope")
	}
	created, err := time.Parse(time.RFC3339Nano, p.CreatedAt)
	if err != nil || spec.ValidateGitOpsProfileContract(*b.Contract, created) != nil {
		return spec.Err(12, "GitOps data source contract was not valid at plan creation")
	}
	d := b.Data
	if d.PVC != r.Spec.Deployment.GitOps.Data.PVC || !spec.ValidGitOpsIdentity(d.UID) || d.Revision == "" || d.Revision != e.Site.Spec.DataRevision || d.BackupRef != e.Site.Spec.BackupRef || b.Preparation != nil && !validGitOpsRunReference(*b.Preparation) {
		return spec.Err(12, "GitOps data claim, declared revision or backup binding differs from this Site")
	}
	if r.Spec.Profile != e.Site.Spec.Profile || needsHardware(r.Spec.AIProfile) || !slices.Contains(e.Site.Spec.AllowedActions, "gitops-data") {
		return spec.Err(10, "GitOps data execution is outside this supported Site profile")
	}
	if p.Kind == "GitOpsDataRecoveryPlan" {
		return e.verifyGitOpsDataRecoveryBinding(p, v)
	}
	from := p.SourceVersion
	if d.Initial {
		from = "install"
	}
	cut, err := gitOpsDataSelection(r, from)
	if err != nil {
		return err
	}
	expectedOps, checks, required := cut.after, r.Spec.Checks, r.Spec.RequiredChecks
	if p.Kind == "GitOpsDataPlan" {
		expectedOps, checks, required = cut.before, gitOpsDataPreChecks(r), []string{}
		if d.Initial || p.SourceRun != "" || d.Predecessor != nil || d.Previous == nil || !validGitOpsRunReference(*d.Previous) || !filepath.IsAbs(d.PreviousManifestPath) || cut.transition.FromDataRevision == "" || cut.transition.FromDataRevision != d.Revision || cut.transition.ToDataRevision == "" || d.BackupRef == "" {
			return spec.Err(12, "pre-adoption data lacks its accepted source, explicit revisions or backup identity")
		}
	} else {
		if b.Contract.ManifestDigest != p.DesiredStateDigest || cut.transition.ToDataRevision == "" || cut.transition.ToDataRevision != d.Revision {
			return spec.Err(12, "post-adoption data needs the reviewed target and declared target revision")
		}
		if d.Initial {
			if p.SourceRun != "" || p.SourceVersion != "" || d.Previous != nil || d.Predecessor != nil || d.PreviousManifestPath != "" {
				return spec.Err(12, "initial data adoption cannot bypass an upgrade handoff")
			}
		} else if d.Predecessor == nil || !validGitOpsRunReference(*d.Predecessor) || p.SourceRun != d.Predecessor.RunID || d.Previous == nil || !validGitOpsRunReference(*d.Previous) || d.BackupRef == "" {
			return spec.Err(12, "post-adoption data lacks the exact predecessor and original backup")
		}
	}
	destructive := false
	for _, op := range expectedOps {
		destructive = destructive || op.Destructive
	}
	if d.Recovery != "" || p.TransitionID != cut.transition.ID || p.TargetVersion != r.Metadata.Version || p.Destructive != destructive || !sameGitOpsValue(p.Operations, expectedOps) || !sameGitOpsValue(p.Checks, checks) || !sameGitOpsValue(p.RequiredChecks, required) {
		return spec.Err(12, "GitOps data operations, checks or transition differ from their signed phase cut")
	}
	models, _, err := gitOpsSignedSeeds(v)
	if err != nil {
		return err
	}
	if (len(models) > 0) != (b.Preparation != nil) {
		return spec.Err(12, "GitOps data has incomplete application artifact provenance")
	}
	for _, op := range p.Operations {
		if op.PVC != "" && op.Type != "seed" && op.PVC != d.PVC {
			return spec.Err(12, "data procedure mounts a claim outside its signed mutable scope")
		}
	}
	if r.Spec.Deployment.Configuration != nil {
		if err := checkSiteConfiguration(r.Spec.Deployment.Configuration, e.Site.Spec.Values); err != nil {
			return err
		}
	}

	return nil
}
