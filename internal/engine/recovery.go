package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) RecoveryPlan(ctx context.Context, runID, recoveryID, bundlePath, sitePath string, policy spec.TrustPolicy) (spec.Plan, error) {
	record, err := e.Store.Run(ctx, runID)
	if err != nil {
		return spec.Plan{}, err
	}
	var original spec.Plan
	if err := spec.Decode(record.Plan, &original); err != nil {
		return spec.Plan{}, err
	}
	if gitOpsPhase(original) || original.GitOps != nil {
		return spec.Plan{}, spec.Err(10, "GitOps source and application-data recovery require their own supported authorized phase; a Helm recovery plan cannot substitute")
	}
	var selected *spec.Recovery
	for i := range original.Recovery {
		r := &original.Recovery[i]
		if r.ID == recoveryID {
			selected = r
		}
	}
	if selected == nil {
		return spec.Plan{}, spec.Err(10, "no declared recovery procedure matches requested identity")
	}
	if !record.Active {
		return spec.Plan{}, spec.Err(10, "source run is terminal; recovery requires an explicit new supported transition")
	}
	verified, err := bundle.Verify(ctx, bundlePath, policy)
	if err != nil {
		return spec.Plan{}, err
	}
	defer verified.Close()
	if verified.Digest != original.BundleDigest {
		return spec.Plan{}, spec.Err(12, "recovery bundle differs from source run's signed bundle")
	}
	snapshot, err := e.Inspect(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	if snapshot.TargetID != record.TargetID || snapshot.NamespaceUID != original.Snapshot.NamespaceUID {
		return spec.Plan{}, spec.Err(11, "recovery target differs from original run")
	}
	p := original
	p.Header.Kind = "RecoveryPlan"
	p.SourceRun = runID
	p.Snapshot = snapshot
	p.SourceVersion = snapshot.InstalledVersion
	p.TargetVersion = selected.ToRelease
	p.Operations = selected.Operations
	p.Checks = selected.Checks
	p.RequiredChecks = nil
	p.Destructive = selected.Destructive
	p.CreatedAt = spec.Now()
	p.Findings = []spec.Finding{}
	p.Executable = true
	p.BundlePath = bundlePath
	p.SitePath = sitePath
	p.SourceSiteDigest, err = sourceSiteDigest(sitePath)
	if err != nil {
		return p, err
	}
	p.SnapshotDigest, err = snapshotDigest(snapshot)
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
	p.PolicyEpoch = policy.Spec.Epoch
	e.addPolicyFloorFindings(ctx, &p)
	for _, c := range selected.Checks {
		if c.Required {
			p.RequiredChecks = append(p.RequiredChecks, c.ID)
		}
	}
	if len(p.RequiredChecks) == 0 {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_ACCEPTANCE_MISSING", Severity: "blocker", Message: "recovery procedure has no required application acceptance checks"})
	}
	if len(p.Operations) == 0 {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_MANUAL_ONLY", Severity: "blocker", Message: "manual-only recovery has no executable operations"})
	}
	if selected.RequiresBackup && e.Site.Spec.BackupRef == "" {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "BACKUP_MISSING", Severity: "blocker", Message: "declared recovery requires a customer-approved backup reference"})
	}
	if selected.DataRevision != "" && selected.DataRevision != e.Site.Spec.DataRevision {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_DATA_MISMATCH", Severity: "blocker", Message: "data revision does not match recovery procedure"})
	}
	var objects []map[string]any
	e.addExecutionFindings(ctx, &p, verified, policy)
	e.addStorageFindings(ctx, &p, verified, policy)
	e.addConfigurationFindings(ctx, &p, verified)
	for _, operation := range p.Operations {
		if operation.Type != "helm" {
			continue
		}
		if p.TargetVersion != verified.Index.Lock.Release.Metadata.Version {
			p.Executable = false
			p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_CHART_UNAVAILABLE", Severity: "blocker", Message: "prior-release Helm recovery requires its separately packaged chart adapter"})
			break
		}
		objects, err = e.render(ctx, verified)
		if err != nil {
			return p, err
		}
		p.DesiredStateDigest, err = spec.Digest(objects)
		if err != nil {
			return p, err
		}
		break
	}
	e.addPermissionFindings(ctx, &p, objects)
	e.addAdmissionFindings(ctx, &p, objects, policy)
	if err := e.recoveryQuiescent(ctx, runID); err != nil {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "RECOVERY_WORKER_UNRESOLVED", Severity: "blocker", Message: err.Error()})
	}
	return p, nil
}

func (e *Engine) recoveryQuiescent(ctx context.Context, runID string) error {
	if err := e.Store.WorkerProtocol(ctx, runID); err != nil {
		return spec.Err(13, "%v", err)
	}
	attempts, err := e.Store.Operations(ctx, runID)
	if err != nil {
		return err
	}
	workers, err := e.Store.Workers(ctx, runID)
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		if attempt.State == "complete" {
			continue
		}
		kind := journalKind(attempt.Intent)
		if kind == "seed" {
			var op spec.Operation
			if err := spec.Decode(attempt.Intent, &op); err != nil {
				return err
			}
			if len(op.Command) == 0 {
				if _, err := e.nativeAttemptStatus(ctx, attempt); err != nil {
					return err
				}
				continue
			}
		}
		if !jobOperation(kind) && kind != "check" {
			if attempt.State == "intent" || attempt.State == "uncertain" {
				return spec.Err(13, "uncertain %s must be reconciled before a recovery mutation", kind)
			}
			continue
		}
		found := false
		for _, worker := range workers {
			if worker.StepID != attempt.StepID || worker.Attempt != attempt.Attempt {
				continue
			}
			if worker.Role == attempt.StepID {
				found = true
			}
			status, err := e.inspectWorker(ctx, worker)
			if err != nil {
				return err
			}
			if status != "complete" && status != "failed" {
				return spec.Err(13, "prior Job is running or unobservable; recovery cannot race it")
			}
			if err := e.nativeWorkerQuiescent(ctx, worker); err != nil {
				return err
			}
		}
		if !found {
			if kind == "check" && fixtureMainNotStarted(attempt) {
				continue
			}
			return spec.Err(13, "prior Job creation has no durable server UID; recovery cannot infer worker termination")
		}
	}
	return nil
}
