package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const modelEnvironment = "CINDERLOCK_MODEL_PROVENANCE"

type modelVolumeBinding struct {
	PVC         string `json:"pvc"`
	PVCUID      string `json:"pvcUID"`
	Manifest    string `json:"manifest"`
	ManifestUID string `json:"manifestUID"`
}

func (e *Engine) modelJobProvenance(ctx context.Context, pvcName, manifestName string) (string, error) {
	pvc, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil || pvc.UID == "" || pvc.DeletionTimestamp != nil {
		return "", spec.Err(13, "model worker PVC identity cannot be bound")
	}
	manifest, err := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, manifestName, metav1.GetOptions{})
	if err != nil || manifest.UID == "" || manifest.DeletionTimestamp != nil || manifest.Annotations["cinderlock.dev/pvc-uid"] != string(pvc.UID) {
		return "", spec.Err(13, "model worker signed manifest identity cannot be bound")
	}
	data, err := spec.Canonical(modelVolumeBinding{PVC: pvcName, PVCUID: string(pvc.UID), Manifest: manifestName, ManifestUID: string(manifest.UID)})
	return string(data), err
}

func (e *Engine) inspectModelJobProvenance(ctx context.Context, job *batchv1.Job) error {
	var binding modelVolumeBinding
	found, needsBinding := false, false
	for _, volume := range job.Spec.Template.Spec.Volumes {
		needsBinding = needsBinding || volume.Name == "manifest" && volume.ConfigMap != nil
	}
	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		if env.Name != modelEnvironment {
			continue
		}
		if found || env.ValueFrom != nil {
			return spec.Err(13, "model worker volume provenance is ambiguous")
		}
		found = true
		if err := spec.Decode([]byte(env.Value), &binding); err != nil {
			return err
		}
	}
	if !needsBinding && !found {
		return nil
	}
	if !found || binding.PVCUID == "" || binding.ManifestUID == "" {
		return spec.Err(13, "model worker predates exact volume provenance; explicit reconciliation is required")
	}
	current, err := e.modelJobProvenance(ctx, binding.PVC, binding.Manifest)
	if err != nil {
		return err
	}
	expected, err := spec.Canonical(binding)
	if err != nil || current != string(expected) {
		return spec.Err(13, "model worker PVC or manifest UID differs from the admitted recipe")
	}
	return nil
}

func (e *Engine) modelVolumeManifest(ctx context.Context, runID string, operation spec.Operation, verified *bundle.Verified) (string, error) {
	asset, err := verified.Asset(operation.Asset)
	if err != nil {
		return "", err
	}
	data, err := modelstage.Manifest(asset.Files)
	if err != nil {
		return "", err
	}
	pvc, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, operation.PVC, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if pvc.UID == "" || pvc.Annotations["cinderlock.dev/model-revision"] != asset.Digest || pvc.Annotations["cinderlock.dev/run"] != runID || pvc.DeletionTimestamp != nil {
		return "", spec.Err(13, "model verification volume identity differs from this seed intent")
	}
	name := jobName(runID, "manifest-"+operation.ID)
	yes := true
	manifest := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.Site.Spec.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "cinderlock", "cinderlock.dev/run": runID}, Annotations: map[string]string{"cinderlock.dev/asset-digest": asset.Digest, "cinderlock.dev/pvc-uid": string(pvc.UID)}}, Immutable: &yes, Data: map[string]string{"files.json": string(data)}}
	_, err = e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Create(ctx, manifest, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return name, getErr
		}
		if existing.Immutable == nil || !*existing.Immutable || existing.Labels["cinderlock.dev/run"] != runID || existing.Annotations["cinderlock.dev/asset-digest"] != asset.Digest || existing.Annotations["cinderlock.dev/pvc-uid"] != string(pvc.UID) || len(existing.Data) != 1 || existing.Data["files.json"] != string(data) || len(existing.BinaryData) != 0 {
			return name, spec.Err(13, "existing model manifest ConfigMap differs from signed seed intent")
		}
		err = nil
	}
	if err != nil {
		return name, err
	}
	return name, nil
}

func (e *Engine) verifySeed(ctx context.Context, runID string, operation spec.Operation, verified *bundle.Verified) (string, error) {
	name, err := e.modelVolumeManifest(ctx, runID, operation, verified)
	if err != nil {
		return name, err
	}
	image, err := e.image(verified, e.Site.Spec.HelperImage)
	if err != nil {
		return name, err
	}
	if operation.ModelSubPath != "" && (operation.ModelSubPath == "." || !spec.SafePath(operation.ModelSubPath)) {
		return name, spec.Err(12, "model subdirectory must be confined within the seeded PVC")
	}
	args := []string{"--root", "/cinderlock-model", "--manifest", "/cinderlock-manifest/files.json"}
	if operation.ModelSubPath != "" {
		args = append(args, "--subpath", operation.ModelSubPath)
	}
	return e.executeJobWithOptions(ctx, runID, "verify-model-"+operation.ID, image, []string{"/usr/local/bin/cinderlock", "helper", "verify-model"}, args, nil, operation.PVC, "/cinderlock-model", operation.TimeoutSeconds, &jobOptions{ReadOnlyPVC: true, ManifestConfigMap: name, IntentStepID: operation.ID, AttemptScoped: len(operation.Command) == 0})
}
