package engine

import (
	"bytes"
	"context"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func sameGitOpsController(a, b spec.GitOpsProfileContract) bool {
	a.AcceptedRevision, a.ManifestDigest, a.NotBefore, a.MaxAgeSeconds = b.AcceptedRevision, b.ManifestDigest, b.NotBefore, b.MaxAgeSeconds
	return sameGitOpsValue(a, b)
}

func (e *Engine) inspectGitOpsData(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) (spec.TargetSnapshot, error) {
	var snapshot spec.TargetSnapshot
	if err := e.verifyGitOpsDataBinding(p, v); err != nil {
		return snapshot, err
	}
	if p.GitOps.Contract.Reversion != nil {
		return snapshot, spec.Err(10, "source reversion requires its separately supported profile; it cannot substitute for a data handoff")
	}
	if _, err := e.gitOpsHistoricalStage(ctx, p.GitOps.Staging, v, false); err != nil {
		return snapshot, err
	}
	for _, path := range []string{e.StateDir, p.SitePath, e.Site.Spec.TrustPolicy, p.GitOps.ManifestPath, p.BundlePath} {
		if _, err := GitOpsPreparationPath(p.GitOps.Contract.Repository, path); err != nil {
			return snapshot, err
		}
	}
	data := p.GitOps.Data
	if data.PreviousManifestPath != "" {
		if _, err := GitOpsPreparationPath(p.GitOps.Contract.Repository, data.PreviousManifestPath); err != nil {
			return snapshot, err
		}
	}
	manifestPath := p.GitOps.ManifestPath
	var previous spec.Plan
	if p.Kind == "GitOpsDataPlan" {
		ref, prior, _, err := e.acceptedGitOpsReference(ctx, *data.Previous)
		if err != nil || ref != *data.Previous {
			return snapshot, spec.Err(11, "original accepted data source no longer matches the exact reference")
		}
		previous = prior
		if previous.GitOps.Data == nil || previous.GitOps.Data.PVC != data.PVC || previous.GitOps.Data.UID != data.UID || previous.Metadata.Channel != p.Metadata.Channel || previous.Metadata.Sequence >= p.Metadata.Sequence || v.Index.Lock.Release.Spec.Deployment.GitOps.Revision != previous.GitOps.Contract.AcceptedRevision {
			return snapshot, spec.Err(11, "upgrade is not bound to the accepted original application/data identity")
		}
		current, err := e.Store.IsAcceptedRelease(ctx, previous.Snapshot.TargetID, previous.Metadata.Application, previous.Metadata.Channel, previous.Metadata.Sequence, previous.BundleDigest)
		if err != nil || !current {
			return snapshot, spec.Err(11, "previous run is not the current accepted release floor")
		}
		if err := e.gitOpsTerminalWorkers(ctx, data.Previous.RunID, false); err != nil {
			return snapshot, err
		}
		future, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
		if err != nil || spec.Hash(future) != p.DesiredStateDigest {
			return snapshot, spec.Err(11, "reviewed target manifest changed")
		}
		objects, err := e.renderWithContext(ctx, v, helmRenderContext{})
		if err != nil {
			return snapshot, spec.Err(10, "verified target render is unavailable")
		}
		rendered, err := encodeObjects(objects)
		if err != nil || !bytes.Equal(rendered, future) {
			return snapshot, spec.Err(12, "future data target differs from the verified bundle render")
		}
		manifestPath = data.PreviousManifestPath
	} else if data.Initial {
		target, _, ok := e.gitOpsProfileTarget(ctx, e.Site)
		if !ok {
			return snapshot, spec.Err(11, "initial data target identity is unavailable")
		}
		accepted, err := e.Store.HasAcceptedRelease(ctx, target, p.Metadata.Application)
		if err != nil || accepted && !e.gitOpsOwnAcceptedRun(ctx, p, target) {
			return snapshot, spec.Err(10, "initial data adoption cannot bypass an already accepted application release")
		}
	} else {
		source, result, err := e.gitOpsDataGate(ctx, p, *data.Predecessor, v)
		if err != nil {
			return snapshot, err
		}
		if source.GitOps.Data.PVC != data.PVC || source.GitOps.Data.UID != data.UID || source.GitOps.Data.BackupRef != data.BackupRef || source.DesiredStateDigest != p.DesiredStateDigest || !sameGitOpsValue(source.GitOps.Staging, p.GitOps.Staging) || !sameGitOpsValue(source.GitOps.Preparation, p.GitOps.Preparation) || !sameGitOpsValue(source.GitOps.Data.Previous, data.Previous) || source.GitOps.Data.PreviousManifestPath != data.PreviousManifestPath || !sameGitOpsController(*source.GitOps.Contract, *p.GitOps.Contract) {
			return snapshot, spec.Err(11, "data handoff changed its original claim, backup, source owner or artifact receipts")
		}
		if p.Kind == "GitOpsDataChecksPlan" {
			if source.Kind != "GitOpsDataPlan" || result.State != "awaiting_adoption" || result.Acceptance != "not_established" || result.Error != "" || source.SourceVersion != p.SourceVersion || source.TransitionID != p.TransitionID || !sameGitOpsValue(source.GitOps.Data.Previous, data.Previous) {
				return snapshot, spec.Err(11, "post-adoption data requires its exact completed pre-adoption result")
			}
			cut, err := gitOpsDataSelection(v.Index.Lock.Release, p.SourceVersion)
			if err != nil || !sameGitOpsValue(source.Operations, cut.before) || source.GitOps.Data.Revision != cut.transition.FromDataRevision {
				return snapshot, spec.Err(12, "predecessor did not execute the signed source-side data procedures")
			}
			finished, fErr := time.Parse(time.RFC3339Nano, result.FinishedAt)
			notBefore, nErr := time.Parse(time.RFC3339Nano, p.GitOps.Contract.NotBefore)
			if fErr != nil || nErr != nil || notBefore.Before(finished.Truncate(time.Second)) {
				return snapshot, spec.Err(10, "post-adoption observation must cover reconciliation after the data predecessor completed")
			}
			if err := e.gitOpsCompletedDataSteps(ctx, data.Predecessor.RunID, source, result); err != nil {
				return snapshot, err
			}
			if err := e.gitOpsTerminalWorkers(ctx, data.Predecessor.RunID, true); err != nil {
				return snapshot, err
			}
		} else {
			if source.Kind != "GitOpsDataChecksPlan" && source.Kind != "GitOpsDataRecoveryPlan" || !gitOpsDataFailure(result) || source.GitOps.Contract.AcceptedRevision != p.GitOps.Contract.AcceptedRevision || source.GitOps.Data.Revision != data.Revision {
				return snapshot, spec.Err(10, "data restore requires an unresolved failed attempt at this exact accepted source")
			}
			if err := e.gitOpsTerminalWorkers(ctx, data.Predecessor.RunID, false); err != nil {
				return snapshot, err
			}
		}
	}
	manifest, err := ReadGitOpsManifest(manifestPath)
	if err != nil {
		return snapshot, err
	}
	observe := func() (GitOpsProfileObservation, error) {
		if p.Kind == "GitOpsDataPlan" {
			out, _, _, err := e.observeAcceptedGitOps(ctx, *data.Previous, policy, p.SitePath, *p.GitOps.Contract, v.Index.Lock.Release.Spec.Deployment.GitOps.Path, manifest)
			return out, err
		}
		if spec.Hash(manifest) != p.DesiredStateDigest {
			return GitOpsProfileObservation{}, spec.Err(11, "reviewed adopted data manifest changed")
		}
		return e.ObserveGitOpsProfile(ctx, v, policy, p.SitePath, *p.GitOps.Contract, manifest)
	}
	observation, err := observe()
	if err != nil || !observation.Ready {
		return snapshot, spec.Err(10, "data source/controller/resource readiness is not established")
	}
	snapshot, err = e.inspectArtifacts(ctx)
	if err != nil {
		return snapshot, err
	}
	observedPlan := p
	if p.Kind == "GitOpsDataPlan" {
		observedPlan.DesiredStateDigest = previous.DesiredStateDigest
	}
	fingerprint, resources, err := gitOpsObservationBindings(observedPlan, observation.BundleDigest, observation)
	if err != nil {
		return snapshot, err
	}
	snapshot.Resources = resources
	snapshot.InstalledVersion = p.SourceVersion
	if p.Kind != "GitOpsDataPlan" {
		snapshot.InstalledVersion = p.TargetVersion
	}
	snapshot.DataRevision = data.Revision
	snapshot.Facts = append(snapshot.Facts, spec.Fact{Name: "gitops/source", Value: fingerprint, Status: "known", Source: "exact accepted source and current controller contract"})
	for _, resource := range observation.Resources {
		snapshot.Facts = append(snapshot.Facts, spec.Fact{Name: "readiness/" + resource.Kind + "/" + resource.Name, Value: "true", Status: "known", Source: "fresh current controller and resource observation"})
	}
	facts, err := e.gitOpsSelectedSecretFacts(ctx, p, v)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, facts...)
	objects, err := PermissionObjects(manifest)
	if err != nil {
		return snapshot, err
	}
	dependencies, err := e.gitOpsWorkloadDependencies(ctx, p, v, objects)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, dependencies...)
	claimFacts, err := e.gitOpsDataClaimFacts(ctx, p, manifest, resources)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, claimFacts...)
	currentManifest, err := ReadGitOpsManifest(manifestPath)
	if err != nil || !bytes.Equal(currentManifest, manifest) {
		return snapshot, spec.Err(11, "data source manifest changed during dependency reads")
	}
	final, err := observe()
	if err != nil || !final.Ready {
		return snapshot, spec.Err(10, "data source observation changed during dependency reads")
	}
	finalFingerprint, finalResources, err := gitOpsObservationBindings(observedPlan, final.BundleDigest, final)
	if err != nil || fingerprint != finalFingerprint || !sameGitOpsValue(resources, finalResources) || observation.TargetID != final.TargetID || observation.NamespaceUID != final.NamespaceUID {
		return snapshot, spec.Err(11, "data source or resource identities changed during dependency reads")
	}
	return gitOpsSortedSnapshot(snapshot), nil
}

func (e *Engine) gitOpsCompletedDataSteps(ctx context.Context, runID string, p spec.Plan, result spec.RunResult) error {
	if len(result.Steps) != len(p.Operations) {
		return spec.Err(13, "data predecessor lacks its complete operation results")
	}
	for _, op := range p.Operations {
		intent, err := e.Store.LatestOperation(ctx, runID, op.ID)
		var recorded spec.Operation
		var step spec.StepResult
		if err != nil || intent.State != "complete" || spec.Decode(intent.Intent, &recorded) != nil || spec.Decode(intent.Evidence, &step) != nil || !sameGitOpsValue(recorded, op) || step.ID != op.ID || step.Attempt != intent.Attempt || step.Status != "pass" || step.Error != "" {
			return spec.Err(13, "data predecessor lacks its exact completed signed operation receipt")
		}
		found := false
		for _, reported := range result.Steps {
			found = found || sameGitOpsValue(reported, step)
		}
		if !found {
			return spec.Err(13, "data predecessor result differs from its original operation receipt")
		}
	}
	return nil
}

func (e *Engine) gitOpsOwnAcceptedRun(ctx context.Context, p spec.Plan, target string) bool {
	current, err := e.Store.ActiveRun(ctx, p.Metadata.Application, e.Site.Spec.Namespace, target)
	digest, dErr := spec.Digest(p)
	if err != nil || dErr != nil || current.PlanDigest != digest || current.BundleDigest != p.BundleDigest {
		return false
	}
	accepted, err := e.Store.IsAcceptedRelease(ctx, target, p.Metadata.Application, p.Metadata.Channel, p.Metadata.Sequence, p.BundleDigest)
	return err == nil && accepted
}

func gitOpsDataFailure(result spec.RunResult) bool {
	if result.Acceptance == "pass" || result.Error == "" {
		return false
	}
	switch result.State {
	case "failed", "recovery_failed", "needs_reconciliation", "stopped":
		return true
	}
	return false
}
