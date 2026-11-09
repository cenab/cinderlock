package engine

import (
	"context"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) acceptedGitOpsReference(ctx context.Context, ref spec.GitOpsRunReference) (spec.GitOpsRunReference, spec.Plan, spec.RunResult, error) {
	var p spec.Plan
	var result spec.RunResult
	record, err := e.Store.Run(ctx, ref.RunID)
	if err != nil || record.Active || record.State != "succeeded" && record.State != "recovered" || spec.Decode(record.Plan, &p) != nil || spec.Decode(record.Result, &result) != nil || !gitOpsApplicationChecks(p) || p.GitOps == nil || p.GitOps.Contract == nil {
		return ref, p, result, spec.Err(10, "previous application acceptance is not an exact inactive successful GitOps run")
	}
	planDigest, pErr := spec.Digest(p)
	resultDigest, rErr := spec.Digest(result)
	metadata, _ := spec.Digest(p.Metadata)
	resultMetadata, _ := spec.Digest(result.Metadata)
	target, namespace, ok := e.gitOpsProfileTarget(ctx, e.Site)
	finished, fErr := time.Parse(time.RFC3339Nano, result.FinishedAt)
	if pErr != nil || rErr != nil || fErr != nil || finished.After(time.Now()) || !ok || spec.ValidateHeader(result.Header, "RunResult") != nil || record.PlanDigest != planDigest || record.BundleDigest != p.BundleDigest || record.Application != p.Metadata.Application || record.Namespace != e.Site.Spec.Namespace || record.TargetID != target || p.Snapshot.TargetID != target || p.Snapshot.NamespaceUID != namespace || p.Snapshot.SiteID != e.Site.Metadata.Name || result.RunID != record.ID || result.PlanDigest != planDigest || result.BundleDigest != record.BundleDigest || result.TargetID != target || result.SiteID != p.Snapshot.SiteID || result.State != record.State || record.State == "recovered" && p.Kind != "GitOpsDataRecoveryPlan" || result.Acceptance != "pass" || result.Error != "" || metadata != resultMetadata || ref.PlanDigest != "" && ref.PlanDigest != planDigest || ref.ResultDigest != "" && ref.ResultDigest != resultDigest {
		return ref, p, result, spec.Err(11, "previous accepted run differs from its exact Plan, result or application target")
	}
	required := map[string]bool{}
	for _, id := range p.RequiredChecks {
		required[id] = false
	}
	for _, check := range result.Checks {
		if _, selected := required[check.ID]; selected && check.Required && check.Status == "pass" {
			required[check.ID] = true
		}
	}
	if len(required) == 0 {
		return ref, p, result, spec.Err(13, "previous accepted run has no required application checks")
	}
	for _, passed := range required {
		if !passed {
			return ref, p, result, spec.Err(13, "previous application acceptance lacks a required passing result")
		}
	}
	return spec.GitOpsRunReference{RunID: record.ID, PlanDigest: planDigest, ResultDigest: resultDigest}, p, result, nil
}

func (e *Engine) observeAcceptedGitOps(ctx context.Context, ref spec.GitOpsRunReference, policy spec.TrustPolicy, sitePath string, contract spec.GitOpsProfileContract, sourcePath string, manifest []byte) (GitOpsProfileObservation, spec.GitOpsRunReference, spec.Plan, error) {
	var out GitOpsProfileObservation
	ref, previous, _, err := e.acceptedGitOpsReference(ctx, ref)
	if err != nil {
		return out, ref, previous, err
	}
	expected, current := *previous.GitOps.Contract, contract
	expected.NotBefore, expected.MaxAgeSeconds = current.NotBefore, current.MaxAgeSeconds
	if a, aErr := spec.Digest(expected); aErr != nil {
		return out, ref, previous, aErr
	} else if b, bErr := spec.Digest(current); bErr != nil || a != b || spec.Hash(manifest) != previous.DesiredStateDigest {
		return out, ref, previous, spec.Err(11, "current old-source observation differs from the accepted controller, source or reviewed manifest")
	}
	out, err = e.observeGitOpsInventory(ctx, policy, sitePath, contract, manifest, gitOpsInventory{digest: previous.BundleDigest, path: sourcePath})
	if err != nil || !out.Ready {
		return out, ref, previous, spec.Err(10, "previous accepted source is not currently ready under its original resource identities")
	}
	fingerprint, resources, err := gitOpsObservationBindings(previous, previous.BundleDigest, out)
	if err != nil {
		return out, ref, previous, err
	}
	bound := false
	for _, fact := range previous.Snapshot.Facts {
		if fact.Name == "gitops/source" && fact.Status == "known" && fact.Value == fingerprint {
			bound = true
		}
	}
	resources = gitOpsSortedSnapshot(spec.TargetSnapshot{Resources: resources}).Resources
	a, aErr := spec.Digest(resources)
	b, bErr := spec.Digest(previous.Snapshot.Resources)
	if !bound || aErr != nil || bErr != nil || a != b {
		return out, ref, previous, spec.Err(11, "current source or resource identities differ from the recorded accepted inventory")
	}
	return out, ref, previous, nil
}
