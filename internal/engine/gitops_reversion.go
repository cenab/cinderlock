package engine

import (
	"bytes"
	"context"
	"unicode/utf8"

	"github.com/cenab/cinderlock/internal/spec"
)

type GitOpsSourceReversion struct {
	Repository       string `json:"repository"`
	PreviousRevision string `json:"previousRevision"`
	RestoredRevision string `json:"restoredRevision"`
}

// GitOpsReversionObservation contains value-only facts about one tracked file.
type GitOpsReversionObservation struct {
	AcceptedRevision string `json:"acceptedRevision"`
	PreviousRevision string `json:"previousRevision"`
	RestoredRevision string `json:"restoredRevision"`
	Path             string `json:"path"`
	PreviousDigest   string `json:"previousDigest"`
	ManifestDigest   string `json:"manifestDigest"`
	Limit            string `json:"limit"`
}

// ObserveGitOpsReversion reads local evidence only; a nil contract yields no facts.
// The caller binds the accepted revision, path, and manifest to its signed contract.
func ObserveGitOpsReversion(ctx context.Context, contract *GitOpsSourceReversion, acceptedRevision, signedPath string, reviewedManifest []byte) (GitOpsReversionObservation, error) {
	var out GitOpsReversionObservation
	if contract == nil {
		return out, nil
	}
	c := *contract
	if !spec.ValidGitOpsCommit(acceptedRevision) || !spec.ValidGitOpsCommit(c.PreviousRevision) || !spec.ValidGitOpsCommit(c.RestoredRevision) || !gitOpsTargetPath(signedPath) || len(reviewedManifest) == 0 || len(reviewedManifest) > maxGitOpsFileBytes || !utf8.Valid(reviewedManifest) || bytes.IndexByte(reviewedManifest, 0) >= 0 {
		return out, spec.Err(2, "GitOps reversion requires exact commits, a confined YAML path, and a bounded text manifest")
	}
	// A no-op proposal reuses the confined HEAD/index/working-file validation.
	source, err := ProposeGitOpsSource(ctx, c.Repository, acceptedRevision, signedPath, reviewedManifest)
	if err != nil {
		return out, spec.Err(spec.ExitCode(err), "GitOps reversion current source validation failed")
	}
	if source.Patch != "" {
		return out, spec.Err(11, "GitOps current file differs from the reviewed manifest")
	}
	git, err := gitOpsExecutable(source.Repository)
	if err != nil {
		return out, spec.Err(10, "an installed local Git executable is required")
	}
	repo := gitOpsRepository{directory: source.Repository, git: git}
	_, restored, err := repo.committedFile(ctx, c.RestoredRevision, signedPath)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(restored, reviewedManifest) {
		return out, spec.Err(11, "GitOps historical restored file differs from the reviewed manifest")
	}
	_, previous, err := repo.committedFile(ctx, c.PreviousRevision, signedPath)
	if err != nil {
		return out, err
	}
	if bytes.Equal(previous, restored) {
		return out, spec.Err(11, "GitOps previous file does not differ from the restored file")
	}
	if _, err := repo.read(ctx, "merge-base", "--is-ancestor", c.RestoredRevision, c.PreviousRevision); err != nil {
		return out, spec.Err(11, "GitOps restored revision is not an established local ancestor of the previous revision")
	}
	if acceptedRevision != c.RestoredRevision {
		if _, err := repo.read(ctx, "merge-base", "--is-ancestor", c.PreviousRevision, acceptedRevision); err != nil {
			return out, spec.Err(11, "GitOps previous revision is not an established local ancestor of the accepted revision")
		}
	}
	after, err := ProposeGitOpsSource(ctx, c.Repository, acceptedRevision, signedPath, reviewedManifest)
	if err != nil || source != after {
		return out, spec.Err(11, "GitOps current source changed during reversion observation")
	}
	return GitOpsReversionObservation{AcceptedRevision: acceptedRevision, PreviousRevision: c.PreviousRevision, RestoredRevision: c.RestoredRevision, Path: signedPath, PreviousDigest: spec.Hash(previous), ManifestDigest: spec.Hash(restored), Limit: "Exact tracked file byte restoration observed locally only; no whole-tree reversion, controller reconciliation, application rollback or acceptance, runtime transition, or data recovery is established."}, nil
}
