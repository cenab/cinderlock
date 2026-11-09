package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (e *Engine) gitOpsPreparedTemplates(ctx context.Context, p spec.Plan, target string, binding gitOpsPreparedVolumeBinding, reviewed map[string]appsv1.Deployment, workers []state.Worker, resources []spec.ResourceFact) error {
	templates, err := e.gitOpsClaimTemplates(ctx)
	if err != nil {
		return err
	}
	for _, item := range templates {
		if !gitOpsUsesClaim(item.Pod, binding.PVC) {
			continue
		}
		if item.Kind == "Job" {
			var original *state.Worker
			for _, worker := range workers {
				if worker.Name == item.Meta.Name && worker.UID == string(item.Meta.UID) {
					copy := worker
					original = &copy
				}
			}
			if original == nil && gitOpsDataPhase(p) {
				proof, err := e.gitOpsDataConsumerJob(ctx, p, "", target, item.Meta)
				if err != nil {
					return err
				}
				original = &proof.worker
			}
			if original == nil {
				return spec.Err(10, "prepared model claim is referenced by an unrecorded pending Job")
			}
			if _, err := e.inspectWorker(ctx, *original); err != nil {
				return err
			}
			if _, err := gitOpsClaimMounts(item.Pod, binding.PVC, "", true); err == nil {
				continue
			}
			if original.RunID != binding.Preparation.RunID {
				return spec.Err(10, "prepared model claim has an unexpected writable Job")
			}
			if status, err := e.modelReceiverStatus(ctx, *original); err != nil || status != "complete" && status != "failed" {
				return spec.Err(13, "original prepared model writer is not confirmed terminal")
			}
			continue
		}
		name, uid := item.Meta.Name, item.Meta.UID
		if item.Kind == "ReplicaSet" {
			owner := metav1.GetControllerOf(&item.Meta)
			if owner == nil || len(item.Meta.OwnerReferences) != 1 || owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" {
				return spec.Err(10, "prepared model ReplicaSet has no exact reviewed Deployment owner")
			}
			name, uid = owner.Name, owner.UID
		} else if item.Kind != "Deployment" || len(item.Meta.OwnerReferences) != 0 {
			return spec.Err(10, "prepared model claim has an unsupported current controller consumer")
		}
		wanted, ok := reviewed[name]
		if !ok || uid == "" || item.Meta.DeletionTimestamp != nil || item.Meta.Namespace != e.Site.Spec.Namespace {
			return spec.Err(10, "prepared model controller is outside the reviewed active identity")
		}
		deployment, err := e.Kube.Client.AppsV1().Deployments(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil || deployment.UID != uid || deployment.DeletionTimestamp != nil {
			return spec.Err(11, "prepared model controller UID changed")
		}
		for _, resource := range resources {
			if resource.Kind == "Deployment" && resource.Name == name && (resource.Namespace != e.Site.Spec.Namespace || resource.UID != string(uid)) {
				return spec.Err(11, "prepared model controller differs from its observed UID")
			}
		}
		expected, err := gitOpsClaimMounts(wanted.Spec.Template.Spec, binding.PVC, binding.SubPath, true)
		if err != nil {
			return err
		}
		actual, err := gitOpsClaimMounts(item.Pod, binding.PVC, binding.SubPath, true)
		a, aErr := spec.Digest(expected)
		b, bErr := spec.Digest(actual)
		if err != nil || aErr != nil || bErr != nil || a != b {
			return spec.Err(10, "prepared model controller template differs from the reviewed read-only mapping")
		}
	}
	return nil
}
