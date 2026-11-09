package engine

import (
	"context"
	"path"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

func (e *Engine) gitOpsPreparedVolume(ctx context.Context, p spec.Plan, v *bundle.Verified, claim string) (gitOpsPreparedVolumeBinding, error) {
	if p.Kind == "GitOpsDataPlan" {
		return e.gitOpsHistoricalVolume(ctx, p, claim)
	}
	var out gitOpsPreparedVolumeBinding
	if e == nil || v == nil || !gitOpsApplicationChecks(p) || p.GitOps == nil || p.GitOps.Preparation == nil || !validGitOpsRunReference(*p.GitOps.Preparation) || p.BundleDigest != v.Digest {
		return out, spec.Err(13, "application claim needs an exact prior native preparation reference")
	}
	if err := e.verifyGitOpsBinding(p, v); err != nil {
		return out, err
	}
	for _, path := range []string{e.StateDir, p.SitePath, e.Site.Spec.TrustPolicy, p.GitOps.ManifestPath} {
		if _, err := GitOpsPreparationPath(p.GitOps.Contract.Repository, path); err != nil {
			return out, err
		}
	}
	var policy spec.TrustPolicy
	if err := spec.Read(e.Site.Spec.TrustPolicy, &policy); err != nil {
		return out, spec.Err(11, "current preparation policy binding is unavailable")
	}
	var ref spec.GitOpsRunReference
	var preparation spec.Plan
	var result spec.RunResult
	var err error
	if gitOpsDataPhase(p) {
		ref, preparation, result, err = e.gitOpsHistoricalPreparation(ctx, *p.GitOps.Preparation, v)
	} else {
		ref, preparation, result, err = e.gitOpsPreparationRecord(ctx, *p.GitOps.Preparation, v, p.SitePath, policy)
	}
	if err != nil {
		return out, err
	}
	if preparation.DesiredStateDigest != p.DesiredStateDigest {
		return out, spec.Err(13, "prepared claim belongs to another reviewed application manifest")
	}
	var selected *spec.Operation
	selectedIndex := 0
	for i, seed := range preparation.Operations {
		if seed.PVC == claim {
			copy := seed
			selected = &copy
			selectedIndex = i
		}
	}
	if selected == nil {
		return out, spec.Err(10, "application claim is outside the signed native preparation selection")
	}
	out.SeedVolumeBinding, err = e.resolveSeedVolumeBinding(ctx, ref.RunID, *selected, v, true)
	if err != nil {
		return out, err
	}
	if err := e.gitOpsSeedReceipt(ctx, ref.RunID, out.SeedVolumeBinding, &result.Steps[selectedIndex]); err != nil {
		return out, err
	}
	worker, err := e.operationWorker(ctx, ref.RunID, selected.ID, out.SeedAttempt, selected.ID)
	if err != nil {
		return out, err
	}
	out.Receiver, err = e.Store.ModelReceiver(ctx, worker)
	if err != nil {
		return out, err
	}
	out.Preparation = ref
	manifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
	if err != nil || spec.Hash(manifest) != p.DesiredStateDigest {
		return out, spec.Err(11, "reviewed prepared-volume mapping changed")
	}
	deployments, err := e.gitOpsClaimDeployments(manifest, *p.GitOps.Contract, claim, out.SubPath)
	if err != nil {
		return out, err
	}
	workers, err := e.Store.Workers(ctx, ref.RunID)
	if err != nil {
		return out, err
	}
	run, err := e.gitOpsActivePlanRun(ctx, p, preparation.Snapshot.TargetID)
	if err != nil {
		return out, err
	}
	if run.ID != "" {
		current, err := e.Store.Workers(ctx, run.ID)
		if err != nil {
			return out, err
		}
		workers = append(workers, current...)
	}
	if err := e.gitOpsPreparedConsumers(ctx, out, deployments, workers, p.Snapshot.Resources); err != nil {
		return out, err
	}
	return out, nil
}

type gitOpsClaimMount struct {
	Container string
	Volume    corev1.Volume
	Mount     corev1.VolumeMount
}

// Only this claim's explicit mapping is projected; commands and configuration
// remain in memory in the reviewed inventory, never in provenance or snapshots.
func gitOpsClaimMounts(pod corev1.PodSpec, claim, subPath string, readOnly bool) ([]gitOpsClaimMount, error) {
	var volume *corev1.Volume
	for _, v := range pod.Volumes {
		if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == claim {
			if volume != nil {
				return nil, spec.Err(10, "prepared application claim has ambiguous volume sources")
			}
			copy := v
			volume = &copy
		}
	}
	if volume == nil {
		return nil, nil
	}
	if len(pod.InitContainers) != 0 || len(pod.EphemeralContainers) != 0 {
		return nil, spec.Err(10, "prepared application claim cannot have init or ephemeral consumers")
	}
	var mounts []gitOpsClaimMount
	for _, container := range pod.Containers {
		for _, device := range container.VolumeDevices {
			if device.Name == volume.Name {
				return nil, spec.Err(10, "prepared application claim cannot be a block device")
			}
		}
		for index, mount := range container.VolumeMounts {
			if mount.Name == volume.Name {
				if readOnly && !mount.ReadOnly || mount.SubPath != subPath || mount.SubPathExpr != "" || !nativeMountSupported(mount.MountPath) {
					return nil, spec.Err(10, "prepared application mount differs from its read-only native subpath")
				}
				for otherIndex, other := range container.VolumeMounts {
					otherPath := path.Clean(other.MountPath)
					if otherIndex != index && (otherPath == "/" || otherPath == mount.MountPath || strings.HasPrefix(otherPath, mount.MountPath+"/") || strings.HasPrefix(mount.MountPath, otherPath+"/")) {
						return nil, spec.Err(10, "prepared application mount is shadowed by another volume")
					}
				}
				mounts = append(mounts, gitOpsClaimMount{Container: container.Name, Volume: *volume, Mount: mount})
			}
		}
	}
	if len(mounts) == 0 {
		return nil, spec.Err(10, "prepared application claim has no explicit read-only mount")
	}
	return mounts, nil
}

func (e *Engine) gitOpsClaimDeployments(manifest []byte, contract spec.GitOpsProfileContract, claim, subPath string) (map[string]appsv1.Deployment, error) {
	objects, err := e.gitOpsProfileInventory(manifest, contract)
	if err != nil {
		return nil, err
	}
	deployments := map[string]appsv1.Deployment{}
	for _, object := range objects {
		if object.GetKind() != "Deployment" {
			continue
		}
		var deployment appsv1.Deployment
		if runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &deployment) != nil {
			return nil, spec.Err(10, "prepared application Deployment mapping is malformed")
		}
		mounts, err := gitOpsClaimMounts(deployment.Spec.Template.Spec, claim, subPath, true)
		if err != nil {
			return nil, err
		}
		if len(mounts) != 0 {
			deployments[deployment.Name] = deployment
		}
	}
	if len(deployments) == 0 {
		return nil, spec.Err(10, "native preparation asset has no explicit reviewed read-only Deployment mapping")
	}
	return deployments, nil
}

func (e *Engine) gitOpsPreparedConsumers(ctx context.Context, binding gitOpsPreparedVolumeBinding, reviewed map[string]appsv1.Deployment, workers []state.Worker, resources []spec.ResourceFact) error {
	if err := e.gitOpsPreparedTemplates(ctx, binding, reviewed, workers, resources); err != nil {
		return err
	}
	pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{Limit: 257})
	if err != nil || pods.Continue != "" || len(pods.Items) > 256 {
		return spec.Err(10, "prepared claim consumer inventory is unavailable or exceeds its bound")
	}
	for _, pod := range pods.Items {
		if !gitOpsUsesClaim(pod.Spec, binding.PVC) {
			continue
		}
		owner := metav1.GetControllerOf(&pod)
		if owner == nil || len(pod.OwnerReferences) != 1 || pod.UID == "" || pod.DeletionTimestamp != nil {
			return spec.Err(10, "prepared claim has an unknown or ambiguous Pod consumer")
		}
		if owner.Kind == "Job" && owner.APIVersion == "batch/v1" {
			var original *state.Worker
			for _, worker := range workers {
				if worker.Name == owner.Name && worker.UID == string(owner.UID) {
					copy := worker
					original = &copy
				}
			}
			if original == nil {
				return spec.Err(13, "prepared claim consumer lacks its original recorded worker identity")
			}
			job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, original.Name, metav1.GetOptions{})
			if err != nil || job.DeletionTimestamp != nil {
				return spec.Err(13, "original prepared claim consumer Job is unavailable")
			}
			if _, err := workerPodRecipe(job, &pod, *original); err != nil {
				return err
			}
			if _, err := e.inspectWorker(ctx, *original); err != nil {
				return err
			}
			if _, err := gitOpsClaimMounts(pod.Spec, binding.PVC, "", true); err == nil {
				continue
			}
			receiver, err := e.Store.ModelReceiver(ctx, *original)
			if err != nil || receiver.PodName != pod.Name || receiver.PodUID != string(pod.UID) || original.RunID != binding.Preparation.RunID {
				return spec.Err(13, "prepared claim has a writable or unconfirmed worker consumer")
			}
			if status, err := e.modelReceiverStatus(ctx, *original); err != nil || status != "complete" && status != "failed" {
				return spec.Err(13, "original prepared claim receiver is not terminal")
			}
			continue
		}
		if owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
			return spec.Err(10, "prepared claim Pod is outside the reviewed Deployment ownership chain")
		}
		rs, err := e.Kube.Client.AppsV1().ReplicaSets(e.Site.Spec.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil || rs.UID == "" || rs.UID != owner.UID || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
			return spec.Err(10, "prepared claim ReplicaSet identity is unavailable or changed")
		}
		controller := metav1.GetControllerOf(rs)
		if controller == nil || controller.Kind != "Deployment" || controller.APIVersion != "apps/v1" {
			return spec.Err(10, "prepared claim ReplicaSet has no exact Deployment owner")
		}
		wanted, ok := reviewed[controller.Name]
		deployment, err := e.Kube.Client.AppsV1().Deployments(e.Site.Spec.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if !ok || err != nil || deployment.UID == "" || deployment.UID != controller.UID || deployment.DeletionTimestamp != nil || len(deployment.OwnerReferences) != 0 {
			return spec.Err(10, "prepared claim consumer is not the current reviewed Deployment UID")
		}
		for _, resource := range resources {
			if resource.Kind == "Deployment" && resource.Name == deployment.Name && (resource.Namespace != e.Site.Spec.Namespace || resource.UID != string(deployment.UID)) {
				return spec.Err(11, "prepared claim Deployment UID differs from the observed plan")
			}
		}
		expected, err := gitOpsClaimMounts(wanted.Spec.Template.Spec, binding.PVC, binding.SubPath, true)
		if err != nil {
			return err
		}
		digest, _ := spec.Digest(expected)
		for _, candidate := range []corev1.PodSpec{deployment.Spec.Template.Spec, rs.Spec.Template.Spec, pod.Spec} {
			mounts, err := gitOpsClaimMounts(candidate, binding.PVC, binding.SubPath, true)
			actual, digestErr := spec.Digest(mounts)
			if err != nil || digestErr != nil || actual != digest {
				return spec.Err(10, "prepared claim consumer differs from the explicit reviewed mount mapping")
			}
		}
		for _, selector := range []*metav1.LabelSelector{deployment.Spec.Selector, rs.Spec.Selector} {
			selected, err := metav1.LabelSelectorAsSelector(selector)
			if err != nil || selector == nil || !selected.Matches(labels.Set(pod.Labels)) {
				return spec.Err(10, "prepared claim consumer does not match its owner selectors")
			}
		}
	}
	return nil
}

func gitOpsUsesClaim(pod corev1.PodSpec, claim string) bool {
	for _, volume := range pod.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim {
			return true
		}
	}
	return false
}

func (e *Engine) gitOpsUnreferencedClaim(ctx context.Context, runID, claim string) error {
	templates, err := e.gitOpsClaimTemplates(ctx)
	if err != nil {
		return err
	}
	var workers []state.Worker
	if runID != "" {
		workers, err = e.Store.Workers(ctx, runID)
		if err != nil {
			return err
		}
	}
	for _, item := range templates {
		if !gitOpsUsesClaim(item.Pod, claim) {
			continue
		}
		if item.Kind != "Job" {
			return spec.Err(10, "native preparation destination is already referenced by an application workload")
		}
		known := false
		for _, worker := range workers {
			if worker.Name == item.Meta.Name && worker.UID == string(item.Meta.UID) {
				job, err := e.workerJob(ctx, worker)
				if err != nil {
					return err
				}
				if job.DeletionTimestamp != nil {
					return spec.Err(13, "native claim consumer differs from its original recorded Job")
				}
				known = true
			}
		}
		if !known {
			return spec.Err(13, "native preparation destination is referenced by an unrecorded Job")
		}
	}
	return nil
}
