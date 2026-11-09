package engine

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// gitOpsPreparedVolumeBinding is historical native provenance, not a fresh
// content scan or authority to mutate an observed application resource.
type gitOpsPreparedVolumeBinding struct {
	seedVolumeBinding
	Preparation spec.GitOpsRunReference `json:"preparation"`
	Receiver    state.ModelReceiver     `json:"receiver"`
}

func (e *Engine) verifyGitOpsPreparation(p spec.Plan, v *bundle.Verified) error {
	if e == nil || p.Kind != "GitOpsPreparePlan" || e.Store == nil || v == nil || p.BundleDigest != v.Digest || spec.ValidateHeader(p.Header, "GitOpsPreparePlan") != nil {
		return spec.Err(12, "native preparation requires its exact local plan and verified bundle")
	}
	if err := e.verifyGitOpsBinding(p, v); err != nil {
		return err
	}
	if len(p.Operations) > 64 || !spec.ValidDigest(e.Site.Spec.HelperImage) {
		return spec.Err(10, "native preparation needs bounded seeds and an independently pinned helper")
	}
	if _, err := e.image(v, e.Site.Spec.HelperImage); err != nil {
		return spec.Err(10, "native preparation helper is not a locked image")
	}
	assets, claims := map[string]bool{}, map[string]bool{}
	for _, seed := range p.Operations {
		expected := spec.Operation{ID: seed.ID, Type: "seed", Asset: seed.Asset, DependsOn: seed.DependsOn, Idempotent: seed.Idempotent, TimeoutSeconds: seed.TimeoutSeconds, PVC: seed.PVC, MountPath: seed.MountPath, ModelSubPath: seed.ModelSubPath, StorageClass: seed.StorageClass, StorageBytes: seed.StorageBytes}
		a, err := spec.Digest(seed)
		b, expectedErr := spec.Digest(expected)
		asset, assetErr := v.Asset(seed.Asset)
		if err != nil || expectedErr != nil || a != b || spec.ValidateOperation(seed) != nil || len(validation.IsDNS1123Subdomain(seed.PVC)) != 0 || !seedAssetID.MatchString(seed.Asset) || assets[seed.Asset] || claims[seed.PVC] || assetErr != nil || !spec.ValidDigest(asset.Digest) || !slices.Contains([]string{"file", "file-tree", "model-tree", "model", "directory"}, asset.Type) {
			return spec.Err(10, "native preparation requires unique exact signed file/model seeds without additional effects")
		}
		if _, err := modelstage.Manifest(asset.Files); err != nil {
			return spec.Err(10, "native preparation file inventory is unsupported")
		}
		for _, other := range v.Index.Lock.Release.Spec.Operations {
			if other.ID != seed.ID && other.PVC == seed.PVC {
				return spec.Err(10, "native preparation revision claims cannot be shared with another operation")
			}
		}
		assets[seed.Asset], claims[seed.PVC] = true, true
	}
	return nil
}

func (e *Engine) gitOpsPreparationReference(ctx context.Context, ref spec.GitOpsRunReference, v *bundle.Verified, sitePath string, policy spec.TrustPolicy) (spec.GitOpsRunReference, error) {
	ref, p, result, err := e.gitOpsPreparationRecord(ctx, ref, v, sitePath, policy)
	if err != nil {
		return ref, err
	}
	for i, seed := range p.Operations {
		binding, err := e.resolveSeedVolumeBinding(ctx, ref.RunID, seed, v, true)
		if err != nil {
			return ref, err
		}
		if err := e.gitOpsSeedReceipt(ctx, ref.RunID, binding, &result.Steps[i]); err != nil {
			return ref, err
		}
	}
	return ref, nil
}

// The phase-wide record is independent of each selected claim's current proof.
// BASE is historical after C; source readiness belongs to the checks contract.
func (e *Engine) gitOpsPreparationRecord(ctx context.Context, ref spec.GitOpsRunReference, v *bundle.Verified, sitePath string, policy spec.TrustPolicy) (spec.GitOpsRunReference, spec.Plan, spec.RunResult, error) {
	if e == nil || v == nil {
		return ref, spec.Plan{}, spec.RunResult{}, spec.Err(13, "native preparation reference needs its local engine and verified bundle")
	}
	ref, p, result, err := e.gitOpsPhaseReference(ctx, ref, "GitOpsPreparePlan", "gitops_prepared", v, sitePath, policy)
	if err != nil {
		return ref, p, result, err
	}
	if err := e.verifyGitOpsPreparation(p, v); err != nil {
		return ref, p, result, err
	}
	target, namespace, ok := e.gitOpsProfileTarget(ctx, e.Site)
	if !ok || target != p.Snapshot.TargetID || namespace != p.Snapshot.NamespaceUID || len(result.Steps) != len(p.Operations) || len(result.Checks) != 0 {
		return ref, p, result, spec.Err(13, "native preparation target or completed result scope changed")
	}
	return ref, p, result, nil
}

func (e *Engine) gitOpsSeedReceipt(ctx context.Context, runID string, binding seedVolumeBinding, reported *spec.StepResult) error {
	intent, err := e.Store.LatestOperation(ctx, runID, binding.SeedID)
	var step spec.StepResult
	worker, workerErr := e.operationWorker(ctx, runID, binding.SeedID, binding.SeedAttempt, binding.SeedID)
	if err != nil || workerErr != nil || spec.Decode(intent.Evidence, &step) != nil || step.ID != binding.SeedID || step.Attempt != binding.SeedAttempt || step.Status != "pass" || step.Error != "" || step.ExternalID != worker.Name {
		return spec.Err(13, "native seed lacks its exact completed receiver receipt")
	}
	if reported != nil {
		a, _ := spec.Digest(step)
		b, _ := spec.Digest(*reported)
		if a != b {
			return spec.Err(13, "preparation result differs from its original completed seed receipt")
		}
	}
	return nil
}

// Only the independently recorded current local run can explain a destination
// that appeared after planning. An annotation is merely a consistency check.
func (e *Engine) gitOpsActivePlanRun(ctx context.Context, p spec.Plan, target string) (state.Run, error) {
	run, err := e.Store.ActiveRun(ctx, p.Metadata.Application, e.Site.Spec.Namespace, target)
	if errors.Is(err, sql.ErrNoRows) {
		return state.Run{}, nil
	}
	if err != nil {
		return state.Run{}, err
	}
	digest, err := spec.Digest(p)
	if err != nil {
		return state.Run{}, err
	}
	var recorded spec.Plan
	if spec.Decode(run.Plan, &recorded) != nil || run.PlanDigest != digest || run.BundleDigest != p.BundleDigest {
		return state.Run{}, spec.Err(13, "current active local run differs from this exact preparation/check plan")
	}
	actual, err := spec.Digest(recorded)
	if err != nil || actual != digest {
		return state.Run{}, spec.Err(13, "active local run plan identity changed")
	}
	return run, nil
}

func (e *Engine) inspectGitOpsPreparation(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) (spec.TargetSnapshot, error) {
	var snapshot spec.TargetSnapshot
	if err := e.verifyGitOpsPreparation(p, v); err != nil {
		return snapshot, err
	}
	if spec.ValidatePolicy(policy) != nil || spec.ValidateSite(e.Site) != nil || needsHardware(v.Index.Lock.Release.Spec.AIProfile) {
		return snapshot, spec.Err(10, "native preparation needs valid explicit inputs without hardware-dependent rendering")
	}
	selectedSite, siteErr := spec.Digest(e.Site)
	selectedPolicy, policyErr := spec.Digest(policy)
	if siteErr != nil || policyErr != nil || selectedSite != p.SiteDigest || selectedPolicy != p.PolicyDigest || p.PolicyEpoch != policy.Spec.Epoch {
		return snapshot, spec.Err(11, "native preparation differs from its selected Site or policy")
	}
	b := p.GitOps
	paths := []string{e.StateDir, p.SitePath, e.Site.Spec.TrustPolicy, b.ManifestPath, p.BundlePath, v.Root, e.Site.Spec.Kubeconfig, e.Site.Spec.RegistryCAFile}
	if e.Site.Spec.HelmPath != "" {
		tool, err := filepath.EvalSymlinks(e.Site.Spec.HelmPath)
		if err != nil {
			return snapshot, spec.Err(10, "selected Helm executable location is unavailable")
		}
		paths = append(paths, tool)
	}
	if ref := e.Site.Spec.SecretRefs[e.Site.Spec.RegistryAuthRef]; ref.File != "" {
		paths = append(paths, ref.File)
	}
	for _, path := range paths {
		if path != "" {
			if _, err := GitOpsPreparationPath(b.Repository, path); err != nil {
				return snapshot, err
			}
		}
	}
	if e.StateDir == "" || p.BundlePath == "" || v.Root == "" || !filepath.IsAbs(b.ManifestPath) {
		return snapshot, spec.Err(2, "native preparation needs external state and an absolute reviewed input")
	}
	siteDigest, policyDigest := "", ""
	if !e.gitOpsProfileFile(p.SitePath, &spec.Site{}, p.SiteDigest, &siteDigest) || !e.gitOpsProfileFile(e.Site.Spec.TrustPolicy, &spec.TrustPolicy{}, p.PolicyDigest, &policyDigest) {
		return snapshot, spec.Err(11, "native preparation Site or policy source differs from the selected inputs")
	}
	if siteDigest != p.SourceSiteDigest {
		return snapshot, spec.Err(11, "native preparation Site source bytes changed")
	}
	target, namespace, ok := e.gitOpsProfileTarget(ctx, e.Site)
	if !ok {
		return snapshot, spec.Err(10, "native preparation explicit target is unavailable")
	}
	history, absent, err := e.helmHistory(ctx)
	if err != nil || !absent && (history.Status != "uninstalled" || history.Revision <= 0) {
		return snapshot, spec.Err(10, "native preparation requires exact selected Helm history absence or uninstalled history")
	}
	manifest, err := ReadGitOpsManifest(b.ManifestPath)
	if err != nil || spec.Hash(manifest) != p.DesiredStateDigest {
		return snapshot, spec.Err(11, "native preparation reviewed input changed")
	}
	objects, err := e.renderWithContext(ctx, v, helmRenderContext{})
	if err != nil {
		return snapshot, spec.Err(10, "native preparation install render is unavailable")
	}
	rendered, err := encodeObjects(objects)
	if err != nil || !bytes.Equal(rendered, manifest) {
		return snapshot, spec.Err(11, "native preparation reviewed manifest differs from the frozen install render")
	}
	if _, err := e.gitOpsProfileInventory(manifest, spec.GitOpsProfileContract{}); err != nil {
		return snapshot, err
	}
	declared := v.Index.Lock.Release.Spec.Deployment.GitOps
	source, err := ProposeGitOpsSource(ctx, b.Repository, declared.Revision, declared.Path, manifest)
	if err != nil || !gitOpsProfileSourceFiles(ctx, source) {
		return snapshot, spec.Err(11, "native preparation signed local BASE commit/path is unavailable or changed")
	}
	if _, err := e.gitOpsStageReference(ctx, b.Staging, v, p.SitePath, policy, false); err != nil {
		return snapshot, err
	}
	snapshot, err = e.inspectArtifacts(ctx)
	if err != nil {
		return snapshot, err
	}
	if target != snapshot.TargetID || namespace != snapshot.NamespaceUID {
		return snapshot, spec.Err(11, "native preparation explicit target changed")
	}
	snapshot.HelmRevision = history.Revision
	secrets, err := e.gitOpsSelectedSecretFacts(ctx, p, v)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, secrets...)
	credentials, err := spec.Digest(snapshot.Facts)
	if err != nil {
		return snapshot, err
	}
	// Store only digests: the inert proposal's patch contains reviewed values.
	scope, err := spec.Digest(struct {
		Source  GitOpsSourceChange
		Seeds   []spec.Operation
		Staging spec.GitOpsRunReference
		Helper  string
	}{source, p.Operations, b.Staging, e.Site.Spec.HelperImage})
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, spec.Fact{Name: "gitops/preparation", Value: scope, Status: "known", Source: "signed local BASE, reviewed install render, fixed native recipes and staged images"})
	seeds, err := e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, snapshot.TargetID)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, seeds...)
	currentArtifacts, err := e.inspectArtifacts(ctx)
	if err != nil {
		return snapshot, err
	}
	currentSecrets, err := e.gitOpsSelectedSecretFacts(ctx, p, v)
	if err != nil {
		return snapshot, err
	}
	currentCredentials, err := spec.Digest(append(currentArtifacts.Facts, currentSecrets...))
	if err != nil || currentCredentials != credentials {
		return snapshot, spec.Err(11, "selected native preparation credentials changed during inspection")
	}
	after, nowAbsent, err := e.helmHistory(ctx)
	if err != nil || nowAbsent != absent || after != history {
		return snapshot, spec.Err(11, "selected Helm history changed during native preparation inspection")
	}
	current, err := ProposeGitOpsSource(ctx, b.Repository, declared.Revision, declared.Path, manifest)
	a, _ := spec.Digest(source)
	c, _ := spec.Digest(current)
	currentManifest, inputErr := ReadGitOpsManifest(b.ManifestPath)
	currentSite, currentPolicy := "", ""
	actualSite, selectedErr := spec.Digest(e.Site)
	currentTarget, currentNamespace, ok := e.gitOpsProfileTarget(ctx, e.Site)
	if err != nil || a != c || inputErr != nil || !bytes.Equal(manifest, currentManifest) || selectedErr != nil || actualSite != selectedSite || spec.ValidatePolicy(policy) != nil || !e.gitOpsProfileFile(p.SitePath, &spec.Site{}, p.SiteDigest, &currentSite) || currentSite != siteDigest || !e.gitOpsProfileFile(e.Site.Spec.TrustPolicy, &spec.TrustPolicy{}, p.PolicyDigest, &currentPolicy) || currentPolicy != policyDigest || !ok || currentTarget != target || currentNamespace != namespace {
		return snapshot, spec.Err(11, "native preparation source, inputs or target changed during inspection")
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	return gitOpsSortedSnapshot(snapshot), nil
}

func (e *Engine) gitOpsPreparationSeedFacts(ctx context.Context, p spec.Plan, v *bundle.Verified, manifest []byte, target string) ([]spec.Fact, error) {
	facts := []spec.Fact{}
	run, err := e.gitOpsActivePlanRun(ctx, p, target)
	if err != nil {
		return nil, err
	}
	for _, seed := range p.Operations {
		if _, err := e.gitOpsClaimDeployments(manifest, spec.GitOpsProfileContract{}, seed.PVC, seed.ModelSubPath); err != nil {
			return nil, err
		}
		if err := e.gitOpsUnreferencedClaim(ctx, run.ID, seed.PVC); err != nil {
			return nil, err
		}
		pvc, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, seed.PVC, metav1.GetOptions{})
		ready := "false"
		if apierrors.IsNotFound(err) {
			if err := e.fixturePodExclusivity(ctx, "", seed.PVC); err != nil {
				return nil, err
			}
			if run.ID != "" {
				if _, err := e.Store.LatestOperation(ctx, run.ID, seed.ID); !errors.Is(err, sql.ErrNoRows) {
					return nil, spec.Err(13, "missing native destination has a prior or unobservable intent; no new attempt is implied")
				}
			}
		} else if err != nil || run.ID == "" || pvc.Annotations["cinderlock.dev/run"] != run.ID {
			return nil, spec.Err(13, "present native destination lacks current active exact-plan local ownership")
		} else {
			intent, err := e.Store.LatestOperation(ctx, run.ID, seed.ID)
			if err != nil {
				return nil, err
			}
			completed := intent.State == "complete"
			binding, err := e.resolveSeedVolumeBinding(ctx, run.ID, seed, v, completed)
			if err != nil {
				return nil, err
			}
			if completed {
				if err := e.gitOpsSeedReceipt(ctx, run.ID, binding, nil); err != nil {
					return nil, err
				}
				ready = "true"
			}
			if err := e.fixturePodExclusivity(ctx, run.ID, seed.PVC); err != nil {
				return nil, err
			}
		}
		facts = append(facts, spec.Fact{Name: "readiness/seed/" + seed.ID, Value: ready, Status: "known", Source: "current original native seed identities and completed receipt"})
	}
	return facts, nil
}
