package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func (e *Engine) gitOpsHistoricalVolume(ctx context.Context, p spec.Plan, claim string) (gitOpsPreparedVolumeBinding, error) {
	var binding gitOpsPreparedVolumeBinding
	if p.GitOps == nil || p.GitOps.Data == nil || p.GitOps.Data.Previous == nil {
		return binding, spec.Err(13, "historical model evidence needs its exact accepted data source")
	}
	ref, previous, _, err := e.acceptedGitOpsReference(ctx, *p.GitOps.Data.Previous)
	if err != nil || ref != *p.GitOps.Data.Previous {
		return binding, spec.Err(13, "historical model source changed")
	}
	evidence := gitOpsSnapshotFact(previous, "gitops/prepared-evidence/"+claim)
	if evidence == "" {
		return binding, spec.Err(13, "historical model has no accepted typed provenance")
	}
	if err := spec.Decode([]byte(evidence), &binding); err != nil {
		return binding, spec.Err(13, "historical model provenance is malformed: %v", err)
	}
	digest, digestErr := spec.Digest(binding)
	if digestErr != nil || binding.PVC != claim || !validGitOpsRunReference(binding.Preparation) || previous.GitOps.Preparation == nil || binding.Preparation != *previous.GitOps.Preparation || gitOpsSnapshotFact(previous, "gitops/prepared-volume/"+claim) != digest {
		return binding, spec.Err(13, "historical model differs from its exact accepted native identities")
	}
	if err := e.validateSeedVolumeBinding(ctx, binding.Preparation.RunID, binding.SeedVolumeBinding, true); err != nil {
		return binding, err
	}
	receiver, err := e.Store.ModelReceiver(ctx, binding.Receiver.Worker)
	if err != nil || !sameGitOpsValue(receiver, binding.Receiver) {
		return binding, spec.Err(13, "historical model receiver identity changed")
	}
	manifest, err := ReadGitOpsManifest(p.GitOps.Data.PreviousManifestPath)
	if err != nil || spec.Hash(manifest) != previous.DesiredStateDigest {
		return binding, spec.Err(11, "historical model's reviewed source mapping changed")
	}
	deployments, err := e.gitOpsClaimDeployments(manifest, *p.GitOps.Contract, claim, binding.SubPath)
	if err != nil {
		return binding, err
	}
	var workers []state.Worker
	current, err := e.gitOpsActivePlanRun(ctx, p, previous.Snapshot.TargetID)
	if err != nil {
		return binding, err
	}
	for _, runID := range []string{binding.Preparation.RunID, ref.RunID, current.ID} {
		if runID == "" {
			continue
		}
		selected, err := e.Store.Workers(ctx, runID)
		if err != nil {
			return binding, err
		}
		workers = append(workers, selected...)
	}
	if err := e.gitOpsPreparedConsumers(ctx, p, binding, deployments, workers, previous.Snapshot.Resources); err != nil {
		return binding, err
	}
	return binding, nil
}
