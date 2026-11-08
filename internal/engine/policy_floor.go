package engine

import (
	"context"
	"errors"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func (e *Engine) policyFloorFinding(ctx context.Context, targetID string, epoch int64, digest string) *spec.Finding {
	var err error
	if e.Store == nil {
		err = errors.New("durable local state is unavailable")
	} else {
		err = e.Store.CheckPolicyFloor(ctx, targetID, epoch, digest)
	}
	if err == nil {
		return nil
	}
	finding := spec.Finding{Code: "POLICY_FLOOR_UNAVAILABLE", Severity: "blocker", Message: "local target policy floor cannot be established", Source: "local policy floor"}
	switch {
	case errors.Is(err, state.ErrPolicyFloorMissing):
		finding.Code = "POLICY_BASELINE_MISSING"
		finding.Message = "independently enroll the exact policy for this target: run cinderlock trust admit-policy --site <site> to preview and approve its policy digest"
	case errors.Is(err, state.ErrPolicyRollback):
		finding.Code = "POLICY_ROLLBACK"
		finding.Message = "policy epoch is below the locally admitted target floor"
	case errors.Is(err, state.ErrPolicyConflict):
		finding.Code = "POLICY_EPOCH_CONFLICT"
		finding.Message = "policy digest differs from the locally admitted policy at this epoch"
	case errors.Is(err, state.ErrPolicyUnadmitted):
		finding.Code = "POLICY_UPDATE_UNADMITTED"
		finding.Message = "policy is ahead of the target floor; admit a verified policy update or use the independent customer enrollment process"
	}
	return &finding
}

func (e *Engine) addPolicyFloorFindings(ctx context.Context, plan *spec.Plan) {
	if finding := e.policyFloorFinding(ctx, plan.Snapshot.TargetID, plan.PolicyEpoch, plan.PolicyDigest); finding != nil {
		plan.Executable = false
		plan.Findings = append(plan.Findings, *finding)
	}
}

func (e *Engine) checkPolicyFloor(ctx context.Context, plan spec.Plan) error {
	if finding := e.policyFloorFinding(ctx, plan.Snapshot.TargetID, plan.PolicyEpoch, plan.PolicyDigest); finding != nil {
		code := 16
		if finding.Code == "POLICY_FLOOR_UNAVAILABLE" {
			code = 13
		}
		return spec.Err(code, "%s: %s", finding.Code, finding.Message)
	}
	return nil
}
