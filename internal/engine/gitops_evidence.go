package engine

import (
	"context"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func validGitOpsRunReference(reference spec.GitOpsRunReference) bool {
	return spec.ValidGitOpsIdentity(reference.RunID) && spec.ValidDigest(reference.PlanDigest) && spec.ValidDigest(reference.ResultDigest)
}

func (e *Engine) gitOpsPhaseReference(ctx context.Context, reference spec.GitOpsRunReference, kind, state string, v *bundle.Verified, sitePath string, policy spec.TrustPolicy) (spec.GitOpsRunReference, spec.Plan, spec.RunResult, error) {
	var p spec.Plan
	var result spec.RunResult
	if e.Store == nil || !spec.ValidGitOpsIdentity(reference.RunID) {
		return reference, p, result, spec.Err(10, "required GitOps phase journal reference is unavailable")
	}
	record, err := e.Store.Run(ctx, reference.RunID)
	if err != nil || record.Active || record.State != state || record.BundleDigest != v.Digest || spec.Decode(record.Plan, &p) != nil || spec.Decode(record.Result, &result) != nil {
		return reference, p, result, spec.Err(10, "required GitOps phase is not a recorded terminal success for this exact bundle")
	}
	planDigest, err := spec.Digest(p)
	resultDigest, resultErr := spec.Digest(result)
	siteDigest, siteErr := spec.Digest(e.Site)
	policyDigest, policyErr := spec.Digest(policy)
	sourceDigest, sourceErr := sourceSiteDigest(sitePath)
	finished, finishedErr := time.Parse(time.RFC3339Nano, result.FinishedAt)
	metadataDigest, _ := spec.Digest(p.Metadata)
	resultMetadata, _ := spec.Digest(result.Metadata)
	releaseMetadata, _ := spec.Digest(v.Index.Lock.Release.Metadata)
	if err != nil || resultErr != nil || siteErr != nil || policyErr != nil || sourceErr != nil || finishedErr != nil || finished.After(time.Now()) || p.Kind != kind || spec.ValidateHeader(result.Header, "RunResult") != nil || record.PlanDigest != planDigest || p.BundleDigest != v.Digest || p.SiteDigest != siteDigest || p.SourceSiteDigest != sourceDigest || p.PolicyDigest != policyDigest || p.PolicyEpoch != policy.Spec.Epoch || p.SitePath != sitePath || p.Snapshot.SiteID != e.Site.Metadata.Name || record.Application != p.Metadata.Application || record.Namespace != e.Site.Spec.Namespace || result.RunID != record.ID || result.SiteID != p.Snapshot.SiteID || result.PlanDigest != planDigest || result.BundleDigest != v.Digest || result.TargetID != p.Snapshot.TargetID || record.TargetID != p.Snapshot.TargetID || result.State != state || result.Acceptance != "not_established" || result.Error != "" || metadataDigest != resultMetadata || metadataDigest != releaseMetadata || reference.PlanDigest != "" && reference.PlanDigest != planDigest || reference.ResultDigest != "" && reference.ResultDigest != resultDigest {
		return reference, p, result, spec.Err(11, "GitOps phase evidence differs from its exact Site, policy, target, recipe or result binding")
	}
	return spec.GitOpsRunReference{RunID: record.ID, PlanDigest: planDigest, ResultDigest: resultDigest}, p, result, nil
}

func (e *Engine) gitOpsStageReference(ctx context.Context, reference spec.GitOpsRunReference, v *bundle.Verified, sitePath string, policy spec.TrustPolicy, full bool) (spec.GitOpsRunReference, error) {
	reference, p, result, err := e.gitOpsPhaseReference(ctx, reference, "ArtifactsPlan", "artifacts_staged", v, sitePath, policy)
	if err != nil {
		return reference, err
	}
	if err = e.verifyArtifactsBinding(p, v); err != nil {
		return reference, err
	}
	snapshot, err := e.inspectArtifacts(ctx)
	if err != nil {
		return reference, err
	}
	digest, err := snapshotDigest(snapshot)
	if err != nil || digest != p.SnapshotDigest {
		return reference, spec.Err(11, "staged image target or private registry credential binding changed")
	}
	if len(result.Steps) != len(p.Operations) {
		return reference, spec.Err(13, "staged image result lacks its complete recorded import scope")
	}
	options, err := e.registryOptions(ctx)
	if err != nil {
		return reference, spec.Err(10, "current admitted registry route or credentials are unavailable")
	}
	for _, op := range p.Operations {
		intent, err := e.Store.LatestOperation(ctx, reference.RunID, op.ID)
		var recorded spec.Operation
		var step spec.StepResult
		expectedDigest, _ := spec.Digest(op)
		if err != nil || intent.State != "complete" || spec.Decode(intent.Intent, &recorded) != nil || spec.Decode(intent.Evidence, &step) != nil {
			return reference, spec.Err(13, "image staging lacks its original completed import intent")
		}
		recordedDigest, _ := spec.Digest(recorded)
		image, err := e.image(v, op.Asset)
		if err != nil || recordedDigest != expectedDigest || step.ID != op.ID || step.Attempt != intent.Attempt || step.Status != "pass" || step.ExternalID != image {
			return reference, spec.Err(13, "image staging import receipt differs from the signed addressed image")
		}
		matched := false
		for _, reported := range result.Steps {
			a, _ := spec.Digest(reported)
			b, _ := spec.Digest(step)
			matched = matched || a == b
		}
		if !matched {
			return reference, spec.Err(13, "staged image result does not retain its exact import receipt")
		}
		destination := strings.TrimSuffix(e.Site.Spec.Registry, "/") + "/" + strings.ToLower(op.Asset)
		if full {
			err = bundle.VerifyImportedImage(ctx, v, op.Asset, destination, options)
		} else {
			err = bundle.ImportedImageAvailable(ctx, v, op.Asset, destination, options)
		}
		if err != nil {
			return reference, spec.Err(10, "staged addressed image closure is unavailable or inconsistent")
		}
	}
	return reference, nil
}

func (e *Engine) gitOpsCoveredSteps(p spec.Plan, v *bundle.Verified) map[string]bool {
	covered := map[string]bool{}
	if !gitOpsPhase(p) {
		return covered
	}
	application, _, _ := gitOpsSignedSeeds(v)
	for _, op := range v.Index.Lock.Release.Spec.Operations {
		if op.Type == "import" || p.Kind == "GitOpsChecksPlan" && op.Type == "gitops" {
			covered[op.ID] = true
		}
	}
	if p.Kind == "GitOpsChecksPlan" && p.GitOps.Preparation != nil {
		for _, seed := range application {
			covered[seed.ID] = true
		}
	}
	return covered
}
