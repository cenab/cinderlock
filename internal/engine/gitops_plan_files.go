package engine

import "github.com/cenab/cinderlock/internal/spec"

func WriteGitOpsPhasePlan(p spec.Plan, output string) error {
	return writeGitOpsPhaseArtifact(p, output, p)
}

func WriteGitOpsPhaseAuthorization(p spec.Plan, authorization spec.Authorization, output string) error {
	return writeGitOpsPhaseArtifact(p, output, authorization)
}

func writeGitOpsPhaseArtifact(p spec.Plan, output string, value any) error {
	if !gitOpsPhase(p) || p.GitOps == nil {
		return spec.Err(2, "GitOps phase output needs its explicit source binding")
	}
	repository := p.GitOps.Repository
	if p.GitOps.Contract != nil {
		repository = p.GitOps.Contract.Repository
	}
	return writeGitOpsArtifact(repository, output, value)
}
