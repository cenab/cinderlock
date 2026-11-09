package engine

import (
	"context"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func (e *Engine) gitOpsDataRun(ctx context.Context, ref spec.GitOpsRunReference, v *bundle.Verified) (spec.GitOpsRunReference, spec.Plan, spec.RunResult, state.Run, error) {
	var p spec.Plan
	var result spec.RunResult
	record, err := e.Store.Run(ctx, ref.RunID)
	if err != nil || spec.Decode(record.Plan, &p) != nil || spec.Decode(record.Result, &result) != nil || !gitOpsDataPhase(p) || p.GitOps == nil || p.GitOps.Data == nil || p.GitOps.Contract == nil {
		return ref, p, result, record, spec.Err(10, "required data phase has no exact durable Plan and result")
	}
	pd, pErr := spec.Digest(p)
	rd, rErr := spec.Digest(result)
	target, namespace, ok := e.gitOpsProfileTarget(ctx, e.Site)
	finished, fErr := time.Parse(time.RFC3339Nano, result.FinishedAt)
	if pErr != nil || rErr != nil || fErr != nil || finished.After(time.Now()) || !ok || record.PlanDigest != pd || record.BundleDigest != v.Digest || p.BundleDigest != v.Digest || record.Application != p.Metadata.Application || record.Namespace != e.Site.Spec.Namespace || p.Snapshot.SiteID != e.Site.Metadata.Name || record.TargetID != target || p.Snapshot.TargetID != target || p.Snapshot.NamespaceUID != namespace || spec.ValidateHeader(result.Header, "RunResult") != nil || result.RunID != record.ID || result.PlanDigest != pd || result.BundleDigest != v.Digest || result.TargetID != target || result.SiteID != p.Snapshot.SiteID || result.State != record.State || result.SourceRun != p.SourceRun || !sameGitOpsValue(result.Metadata, p.Metadata) || !sameGitOpsValue(p.Metadata, v.Index.Lock.Release.Metadata) || ref.PlanDigest != "" && ref.PlanDigest != pd || ref.ResultDigest != "" && ref.ResultDigest != rd {
		return ref, p, result, record, spec.Err(11, "data predecessor differs from its exact bundle, target, Plan or result")
	}
	return spec.GitOpsRunReference{RunID: record.ID, PlanDigest: pd, ResultDigest: rd}, p, result, record, nil
}

func (e *Engine) gitOpsDataGate(ctx context.Context, p spec.Plan, ref spec.GitOpsRunReference, v *bundle.Verified) (spec.Plan, spec.RunResult, error) {
	bound, source, result, record, err := e.gitOpsDataRun(ctx, ref, v)
	if err != nil {
		return source, result, err
	}
	if bound != ref || p.SourceRun != ref.RunID {
		return source, result, spec.Err(11, "data handoff lacks its exact source reference")
	}
	if !record.Active {
		current, err := e.Store.ActiveRun(ctx, p.Metadata.Application, e.Site.Spec.Namespace, record.TargetID)
		successor, sErr := e.Store.Successor(ctx, record.ID)
		pd, pErr := spec.Digest(p)
		if err != nil || sErr != nil || pErr != nil || current.PlanDigest != pd || current.BundleDigest != p.BundleDigest || successor != current.ID {
			return source, result, spec.Err(13, "inactive data predecessor has no exact admitted active successor")
		}
	}
	if err := e.verifyClusterRecord(ctx, record.ID, record.PlanDigest); err != nil {
		return source, result, err
	}
	return source, result, nil
}
