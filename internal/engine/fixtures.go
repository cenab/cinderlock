package engine

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const fixtureEnvironment = "CINDERLOCK_FIXTURE_PROVENANCE"

var fixtureID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func reservedJobEnvironment(name string) bool {
	return name == fixtureEnvironment || name == modelEnvironment || name == "CINDERLOCK_RUN_ID" || name == "CINDERLOCK_OPERATION_ID"
}

// fixtureBinding is durable acceptance evidence, not an assertion that a storage
// administrator cannot change bytes below the Kubernetes API.
type fixtureBinding struct {
	AssetID        string       `json:"assetID"`
	AssetDigest    string       `json:"assetDigest"`
	SeedID         string       `json:"seedID"`
	SeedDigest     string       `json:"seedDigest"`
	SeedAttempt    int          `json:"seedAttempt"`
	PVC            string       `json:"pvc"`
	PVCUID         string       `json:"pvcUID"`
	SubPath        string       `json:"subPath,omitempty"`
	Manifest       string       `json:"manifest"`
	ManifestUID    string       `json:"manifestUID"`
	ManifestDigest string       `json:"manifestDigest"`
	Verifier       state.Worker `json:"verifier"`
}

func fixtureMount(id string) string { return "/cinderlock-fixtures/" + id }
func fixtureVerifierRole(checkID, assetID string) string {
	return "@fixture/" + checkID + "/" + assetID
}

func fixtureSeeds(p spec.Plan, c spec.Check) ([]spec.Operation, error) {
	if len(c.Fixtures) > 16 || len(c.Fixtures) > 0 && c.Type != "job" {
		return nil, spec.Err(10, "fixtures require a Job check with at most sixteen assets")
	}
	selected := make([]spec.Operation, 0, len(c.Fixtures))
	seen := map[string]bool{}
	for _, id := range c.Fixtures {
		if !fixtureID.MatchString(id) || seen[id] {
			return nil, spec.Err(10, "fixture IDs must be distinct confined asset identifiers")
		}
		seen[id] = true
		var candidates []spec.Operation
		for _, op := range p.Operations {
			if op.Type == "seed" && op.Asset == id {
				candidates = append(candidates, op)
			}
		}
		if len(candidates) != 1 || len(candidates[0].Command) != 0 || candidates[0].PVC == "" {
			return nil, spec.Err(10, "fixture %s needs exactly one selected native seed with its own PVC", id)
		}
		seed := candidates[0]
		for _, other := range p.Operations {
			if other.ID != seed.ID && other.PVC == seed.PVC {
				return nil, spec.Err(10, "fixture PVC %s is shared with another operation", seed.PVC)
			}
		}
		selected = append(selected, seed)
	}
	return selected, nil
}

func referencesFixture(value any, pvc string) bool {
	switch node := value.(type) {
	case map[string]any:
		if node["claimName"] == pvc {
			return true
		}
		if node["kind"] == "PersistentVolumeClaim" {
			metadata, _ := node["metadata"].(map[string]any)
			if metadata["name"] == pvc {
				return true
			}
		}
		for _, child := range node {
			if referencesFixture(child, pvc) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if referencesFixture(child, pvc) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) fixtureFindings(ctx context.Context, p spec.Plan, v *bundle.Verified) []spec.Finding {
	findings := []spec.Finding{}
	block := func(err error) {
		findings = append(findings, spec.Finding{Code: "CHECK_FIXTURE_UNSUPPORTED", Severity: "blocker", Message: err.Error(), Source: "dedicated native fixture profile"})
	}
	var objects []map[string]any
	needsChart, needsFixtures := false, false
	for _, op := range p.Operations {
		needsChart = needsChart || op.Type == "helm"
	}
	for _, check := range p.Checks {
		needsFixtures = needsFixtures || len(check.Fixtures) > 0
	}
	if !needsFixtures {
		return findings
	}
	if needsChart {
		var err error
		objects, err = e.render(ctx, v)
		if err != nil {
			block(spec.Err(10, "fixture exclusivity needs a supported rendered chart"))
			return findings
		}
	}
	for _, check := range p.Checks {
		seeds, err := fixtureSeeds(p, check)
		if err != nil {
			block(err)
			continue
		}
		for _, seed := range seeds {
			asset, err := v.Asset(seed.Asset)
			if err != nil || asset.Type == "image" {
				block(spec.Err(10, "fixture %s must be a locked file or file tree", seed.Asset))
				continue
			}
			if _, err = modelstage.Manifest(asset.Files); err != nil {
				block(err)
				continue
			}
			for _, object := range objects {
				if referencesFixture(object, seed.PVC) {
					block(spec.Err(10, "fixture PVC %s must be separate from chart resources and workloads", seed.PVC))
				}
			}
			pvc, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, seed.PVC, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				if err := e.fixturePodExclusivity(ctx, "", seed.PVC); err != nil {
					block(err)
				}
				continue
			}
			if err != nil {
				block(spec.Err(10, "fixture PVC identity cannot be inspected"))
				continue
			}
			if e.Store == nil {
				block(spec.Err(13, "fixture provenance needs durable run state"))
				continue
			}
			run, err := e.Store.Run(ctx, pvc.Annotations["cinderlock.dev/run"])
			digest, digestErr := spec.Digest(p)
			if err != nil || digestErr != nil || run.PlanDigest != digest {
				block(spec.Err(10, "existing fixture PVC is not owned by this exact planned run"))
				continue
			}
			if _, err = e.resolveFixtureBindings(ctx, run.ID, p, check, v); err != nil {
				block(err)
			}
		}
	}
	return findings
}

func (e *Engine) fixtureRunPlan(ctx context.Context, runID string) (spec.Plan, error) {
	var p spec.Plan
	if e.Store == nil {
		return p, spec.Err(13, "fixture acceptance needs durable run state")
	}
	run, err := e.Store.Run(ctx, runID)
	if err != nil {
		return p, err
	}
	if err := spec.Decode(run.Plan, &p); err != nil {
		return p, err
	}
	digest, err := spec.Digest(p)
	if err != nil || digest != run.PlanDigest {
		return p, spec.Err(13, "fixture run plan differs from its admitted digest")
	}
	return p, nil
}

func (e *Engine) resolveFixtureBindings(ctx context.Context, runID string, p spec.Plan, c spec.Check, v *bundle.Verified) ([]fixtureBinding, error) {
	if v == nil || p.BundleDigest != v.Digest {
		return nil, spec.Err(13, "fixture bundle differs from the admitted plan")
	}
	seeds, err := fixtureSeeds(p, c)
	if err != nil {
		return nil, err
	}
	bindings := make([]fixtureBinding, 0, len(seeds))
	for _, seed := range seeds {
		asset, err := v.Asset(seed.Asset)
		if err != nil || asset.Type == "image" {
			return nil, spec.Err(13, "fixture is not a locked file artifact")
		}
		manifest, err := modelstage.Manifest(asset.Files)
		if err != nil {
			return nil, err
		}
		intent, err := e.Store.LatestOperation(ctx, runID, seed.ID)
		if err != nil || intent.State != "complete" {
			return nil, spec.Err(13, "fixture seed has not completed in this run")
		}
		seedDigest, _ := spec.Digest(seed)
		var recorded spec.Operation
		if err := spec.Decode(intent.Intent, &recorded); err != nil {
			return nil, err
		}
		if recordedDigest, err := spec.Digest(recorded); err != nil || recordedDigest != seedDigest {
			return nil, spec.Err(13, "fixture seed intent differs from the selected operation")
		}
		verifier, err := e.operationWorker(ctx, runID, seed.ID, intent.Attempt, "verify-model-"+seed.ID)
		if err != nil {
			return nil, err
		}
		pvc, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, seed.PVC, metav1.GetOptions{})
		if err != nil {
			return nil, spec.Err(13, "fixture PVC cannot be observed")
		}
		cm, err := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, jobName(runID, "manifest-"+seed.ID), metav1.GetOptions{})
		if err != nil || cm.UID == "" || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || cm.Data["files.json"] != string(manifest) || len(cm.BinaryData) != 0 || cm.Annotations["cinderlock.dev/pvc-uid"] != string(pvc.UID) || cm.Labels["cinderlock.dev/run"] != runID || cm.Annotations["cinderlock.dev/asset-digest"] != asset.Digest {
			return nil, spec.Err(13, "fixture manifest or original PVC identity differs from the signed seed")
		}
		binding := fixtureBinding{AssetID: seed.Asset, AssetDigest: asset.Digest, SeedID: seed.ID, SeedDigest: seedDigest, SeedAttempt: intent.Attempt, PVC: seed.PVC, PVCUID: string(pvc.UID), SubPath: seed.ModelSubPath, Manifest: cm.Name, ManifestUID: string(cm.UID), ManifestDigest: spec.Hash(manifest), Verifier: verifier}
		if err := e.validateFixtureBinding(ctx, runID, binding); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func (e *Engine) validateFixtureBinding(ctx context.Context, runID string, binding fixtureBinding) error {
	if binding.PVCUID == "" || binding.ManifestUID == "" || binding.SeedAttempt < 1 || !fixtureID.MatchString(binding.AssetID) || !spec.ValidDigest(binding.AssetDigest) || !spec.ValidDigest(binding.ManifestDigest) || binding.Verifier.RunID != runID || binding.Verifier.StepID != binding.SeedID || binding.Verifier.Attempt != binding.SeedAttempt || binding.Verifier.Role != "verify-model-"+binding.SeedID {
		return spec.Err(13, "fixture provenance is incomplete")
	}
	pvc, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, binding.PVC, metav1.GetOptions{})
	if err != nil || string(pvc.UID) != binding.PVCUID || pvc.DeletionTimestamp != nil || pvc.Annotations["cinderlock.dev/run"] != runID || pvc.Annotations["cinderlock.dev/model-revision"] != binding.AssetDigest || len(pvc.OwnerReferences) > 0 || len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce || pvc.Spec.DataSource != nil || pvc.Spec.DataSourceRef != nil || pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode != corev1.PersistentVolumeFilesystem {
		return spec.Err(13, "fixture PVC UID, ownership or dedicated filesystem profile changed")
	}
	cm, err := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, binding.Manifest, metav1.GetOptions{})
	if err != nil || string(cm.UID) != binding.ManifestUID || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || spec.Hash([]byte(cm.Data["files.json"])) != binding.ManifestDigest || len(cm.BinaryData) != 0 || cm.Annotations["cinderlock.dev/pvc-uid"] != binding.PVCUID || cm.Annotations["cinderlock.dev/asset-digest"] != binding.AssetDigest || cm.Labels["cinderlock.dev/run"] != runID {
		return spec.Err(13, "fixture immutable manifest identity changed")
	}
	intent, err := e.Store.LatestOperation(ctx, runID, binding.SeedID)
	if err != nil || intent.State != "complete" || intent.Attempt != binding.SeedAttempt {
		return spec.Err(13, "fixture seed is no longer the completed admitted attempt")
	}
	var operation spec.Operation
	if err := spec.Decode(intent.Intent, &operation); err != nil {
		return err
	}
	digest, err := spec.Digest(operation)
	if err != nil || digest != binding.SeedDigest || operation.Asset != binding.AssetID || operation.PVC != binding.PVC || operation.ModelSubPath != binding.SubPath || operation.Type != "seed" || len(operation.Command) != 0 {
		return spec.Err(13, "fixture seed provenance changed")
	}
	worker, err := e.operationWorker(ctx, runID, binding.SeedID, binding.SeedAttempt, binding.SeedID)
	if err != nil {
		return err
	}
	if status, err := e.modelReceiverStatus(ctx, worker); err != nil || status != "complete" {
		return spec.Err(13, "fixture native receiver is not confirmed complete")
	}
	stored, err := e.operationWorker(ctx, runID, binding.SeedID, binding.SeedAttempt, binding.Verifier.Role)
	if err != nil {
		return err
	}
	a, _ := spec.Digest(stored)
	b, _ := spec.Digest(binding.Verifier)
	if a != b {
		return spec.Err(13, "fixture original verifier identity changed")
	}
	if status, err := e.inspectWorker(ctx, stored); err != nil || status != "complete" {
		return spec.Err(13, "fixture original signed-manifest verification is not confirmed complete")
	}
	return e.fixturePodExclusivity(ctx, runID, binding.PVC)
}

// Known original receivers may have written the PVC only after becoming
// terminal. All other current consumers must be admitted read-only workers.
func (e *Engine) fixturePodExclusivity(ctx context.Context, runID, pvc string) error {
	pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{Limit: 257})
	if err != nil || pods.Continue != "" || len(pods.Items) > 256 {
		return spec.Err(10, "fixture consumer inventory is unavailable or exceeds its bound")
	}
	var workers []state.Worker
	if runID != "" {
		workers, err = e.Store.Workers(ctx, runID)
		if err != nil {
			return err
		}
	}
	for _, pod := range pods.Items {
		volumes := map[string]bool{}
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == pvc {
				volumes[volume.Name] = volume.PersistentVolumeClaim.ReadOnly
			}
		}
		if len(volumes) == 0 {
			continue
		}
		owner := metav1.GetControllerOf(&pod)
		var matched *state.Worker
		for _, worker := range workers {
			if owner != nil && owner.Kind == "Job" && owner.APIVersion == "batch/v1" && owner.Name == worker.Name && string(owner.UID) == worker.UID {
				copy := worker
				matched = &copy
				break
			}
		}
		if matched == nil {
			return spec.Err(10, "fixture PVC is shared with an unrecognized Pod")
		}
		job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, matched.Name, metav1.GetOptions{})
		if err != nil {
			return spec.Err(13, "fixture consumer Job cannot be observed")
		}
		if _, err := modelPodRecipe(job, &pod, *matched); err != nil {
			return err
		}
		readOnly := len(pod.Spec.InitContainers) == 0 && len(pod.Spec.EphemeralContainers) == 0
		for _, container := range pod.Spec.Containers {
			for _, mount := range container.VolumeMounts {
				if sourceRO, uses := volumes[mount.Name]; uses && (!sourceRO || !mount.ReadOnly) {
					readOnly = false
				}
			}
		}
		if readOnly {
			continue
		}
		receiver, err := e.Store.ModelReceiver(ctx, *matched)
		if err != nil || receiver.PodUID != string(pod.UID) || (pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed) {
			return spec.Err(13, "fixture PVC has a writable or unconfirmed consumer")
		}
		if status, err := e.modelReceiverStatus(ctx, *matched); err != nil || status != "complete" && status != "failed" {
			return spec.Err(13, "fixture seed writer is not terminal")
		}
	}
	return nil
}

func (e *Engine) validateCheckFixtures(ctx context.Context, runID string, p spec.Plan, c spec.Check, bindings []fixtureBinding, requireFresh bool) error {
	seeds, err := fixtureSeeds(p, c)
	if err != nil {
		return err
	}
	if len(seeds) != len(bindings) {
		return spec.Err(13, "acceptance fixture bindings differ from declared assets")
	}
	for index, seed := range seeds {
		binding := bindings[index]
		digest, _ := spec.Digest(seed)
		if binding.AssetID != seed.Asset || binding.SeedDigest != digest || binding.SeedID != seed.ID || binding.PVC != seed.PVC || binding.SubPath != seed.ModelSubPath {
			return spec.Err(13, "acceptance fixture binding differs from selected native seed")
		}
		if err := e.validateFixtureBinding(ctx, runID, binding); err != nil {
			return err
		}
		if requireFresh {
			intent, err := e.Store.LatestOperation(ctx, runID, checkStepID(c.ID))
			if err != nil {
				return err
			}
			worker, err := e.operationWorker(ctx, runID, intent.StepID, intent.Attempt, fixtureVerifierRole(c.ID, binding.AssetID))
			if err != nil {
				return err
			}
			if status, err := e.inspectWorker(ctx, worker); err != nil || status != "complete" {
				return spec.Err(13, "fixture verification for this acceptance attempt is not confirmed complete")
			}
		}
	}
	return nil
}

func (e *Engine) verifyCheckFixtures(ctx context.Context, runID string, c spec.Check, bindings []fixtureBinding, v *bundle.Verified) error {
	image, err := e.image(v, e.Site.Spec.HelperImage)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if err := e.validateFixtureBinding(ctx, runID, binding); err != nil {
			return err
		}
		args := []string{"--root", "/cinderlock-model", "--manifest", "/cinderlock-manifest/files.json"}
		if binding.SubPath != "" {
			args = append(args, "--subpath", binding.SubPath)
		}
		_, err = e.executeJobWithOptions(ctx, runID, fixtureVerifierRole(c.ID, binding.AssetID), image, []string{"/usr/local/bin/cinderlock", "helper", "verify-model"}, args, nil, binding.PVC, "/cinderlock-model", c.TimeoutSeconds, &jobOptions{ReadOnlyPVC: true, ManifestConfigMap: binding.Manifest, IntentStepID: checkStepID(c.ID)})
		if err != nil {
			return err
		}
		if err := e.validateFixtureBinding(ctx, runID, binding); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) mountedFixtureBindings(ctx context.Context, job *batchv1.Job, runID string) error {
	var bindings []fixtureBinding
	found := false
	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		if env.Name != fixtureEnvironment {
			continue
		}
		if found || env.ValueFrom != nil {
			return spec.Err(13, "fixture provenance environment is ambiguous")
		}
		found = true
		if err := spec.Decode([]byte(env.Value), &bindings); err != nil {
			return err
		}
	}
	if !found {
		return nil
	}
	if len(bindings) == 0 {
		return spec.Err(13, "fixture worker has empty provenance")
	}
	for _, binding := range bindings {
		if err := e.validateFixtureBinding(ctx, runID, binding); err != nil {
			return err
		}
	}
	return nil
}

func appendFixtureVolumes(container *corev1.Container, volumes *[]corev1.Volume, bindings []fixtureBinding) error {
	if len(bindings) == 0 {
		return nil
	}
	for _, env := range container.Env {
		if env.Name == fixtureEnvironment {
			return spec.Err(10, "Job secret name conflicts with fixed fixture provenance")
		}
	}
	data, err := spec.Canonical(bindings)
	if err != nil {
		return err
	}
	container.Env = append(container.Env, corev1.EnvVar{Name: fixtureEnvironment, Value: string(data)})
	for i, binding := range bindings {
		name := fmt.Sprintf("fixture-%d", i)
		*volumes = append(*volumes, corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: binding.PVC, ReadOnly: true}}})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: name, MountPath: fixtureMount(binding.AssetID), SubPath: binding.SubPath, ReadOnly: true})
	}
	return nil
}

func fixtureIntentBindings(raw []byte) ([]fixtureBinding, error) {
	var intent checkIntent
	if err := spec.Decode(raw, &intent); err != nil {
		return nil, err
	}
	return intent.Fixtures, nil
}
