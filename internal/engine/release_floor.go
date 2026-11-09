package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) releaseFloorFinding(ctx context.Context, p spec.Plan) *spec.Finding {
	floor, err := e.Store.ReleaseFloor(ctx, p.Snapshot.TargetID, p.Metadata.Application, p.Metadata.Channel)
	if err != nil {
		return &spec.Finding{Code: "RELEASE_FLOOR_UNAVAILABLE", Severity: "blocker", Message: "local accepted-release floor is unavailable"}
	}
	if p.Metadata.Sequence < floor {
		return &spec.Finding{Code: "RELEASE_REPLAY", Severity: "blocker", Message: "release sequence is lower than the locally accepted high-water sequence"}
	}
	return nil
}

func (e *Engine) addReleaseFloorFindings(ctx context.Context, p *spec.Plan) {
	if finding := e.releaseFloorFinding(ctx, *p); finding != nil {
		p.Executable = false
		p.Findings = append(p.Findings, *finding)
	}
}
