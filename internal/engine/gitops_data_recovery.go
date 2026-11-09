package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) GitOpsDataRecoveryPlan(ctx context.Context, sourceRun, recoveryID string, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, binding spec.GitOpsPlanBinding) (spec.Plan, error) {
	var p spec.Plan
	if e == nil || e.Store == nil || v == nil || spec.ValidateRelease(v.Index.Lock.Release) != nil || spec.ValidatePolicy(policy) != nil || spec.ValidateSite(e.Site) != nil || binding.Contract == nil {
		return p, spec.Err(2, "data recovery needs verified current inputs and an explicit same-source contract")
	}
	ref, source, result, record, err := e.gitOpsDataRun(ctx, spec.GitOpsRunReference{RunID: sourceRun}, v)
	if err != nil {
		return p, err
	}
	if !record.Active || source.Kind != "GitOpsDataChecksPlan" && source.Kind != "GitOpsDataRecoveryPlan" || !gitOpsDataFailure(result) {
		return p, spec.Err(10, "same-source data recovery requires an unresolved failed post-adoption run")
	}
	r := v.Index.Lock.Release
	var selected *spec.Recovery
	for i := range r.Spec.Recovery {
		if r.Spec.Recovery[i].ID == recoveryID {
			selected = &r.Spec.Recovery[i]
		}
	}
	if selected == nil || selected.GitOpsData == nil || selected.ToRelease != r.Metadata.Version {
		return p, spec.Err(10, "same-source data recovery needs an explicitly signed supported restore recipe")
	}
	operations, err := gitOpsDataRecoverySelection(*selected)
	if err != nil {
		return p, err
	}
	data := *source.GitOps.Data
	data.Predecessor = &ref
	data.Initial = false
	data.Recovery = recoveryID
	data.Revision = e.Site.Spec.DataRevision
	data.BackupRef = e.Site.Spec.BackupRef
	binding.Data = &data
	binding.Repository = ""
	binding.Staging = source.GitOps.Staging
	binding.Preparation = source.GitOps.Preparation
	p = spec.Plan{Header: spec.NewHeader("GitOpsDataRecoveryPlan"), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, GitOps: &binding, DesiredStateDigest: source.DesiredStateDigest, SourceRun: sourceRun, SourceVersion: r.Metadata.Version, TargetVersion: selected.ToRelease, TransitionID: recoveryID, Operations: operations, Checks: selected.Checks, RequiredChecks: []string{}, Recovery: r.Spec.Recovery, Destructive: selected.Destructive, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch, Findings: []spec.Finding{}}
	p.Metadata = r.Metadata
	for _, check := range selected.Checks {
		if check.Required {
			p.RequiredChecks = append(p.RequiredChecks, check.ID)
		}
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
	manifest, err := ReadGitOpsManifest(binding.ManifestPath)
	if err != nil {
		return p, err
	}
	objects, err := PermissionObjects(manifest)
	if err != nil {
		return p, err
	}
	e.addPermissionFindings(ctx, &p, objects)
	return p, nil
}

func (e *Engine) verifyGitOpsDataRecoveryBinding(p spec.Plan, v *bundle.Verified) error {
	r := v.Index.Lock.Release
	d := p.GitOps.Data
	if d.Initial || d.Predecessor == nil || !validGitOpsRunReference(*d.Predecessor) || p.SourceRun != d.Predecessor.RunID || d.Recovery == "" || p.SourceVersion != r.Metadata.Version || p.TargetVersion != r.Metadata.Version || p.GitOps.Contract.ManifestDigest != p.DesiredStateDigest {
		return spec.Err(12, "data recovery is not an exact same-source authorized handoff")
	}
	for _, recovery := range r.Spec.Recovery {
		if recovery.ID != d.Recovery {
			continue
		}
		operations, err := gitOpsDataRecoverySelection(recovery)
		if err != nil {
			return err
		}
		if recovery.GitOpsData == nil || recovery.GitOpsData.PVC != d.PVC || recovery.ToRelease != r.Metadata.Version || recovery.DataRevision == "" || recovery.DataRevision != d.Revision || recovery.RequiresBackup && d.BackupRef == "" || p.TransitionID != recovery.ID || p.Destructive != recovery.Destructive || !sameGitOpsValue(p.Operations, operations) || !sameGitOpsValue(p.Checks, recovery.Checks) {
			return spec.Err(12, "data recovery differs from the signed restore, revision or backup precondition")
		}
		required := []string{}
		workflow := false
		for _, check := range recovery.Checks {
			if check.Required {
				required = append(required, check.ID)
				workflow = workflow || check.Domain == "workflow" || check.Domain == "recovery"
			}
		}
		if len(p.Operations) == 0 || !workflow || !sameGitOpsValue(p.RequiredChecks, required) {
			return spec.Err(10, "data recovery needs executable procedures and required application checks")
		}
		return nil
	}
	return spec.Err(12, "data recovery recipe is not signed by the selected bundle")
}
